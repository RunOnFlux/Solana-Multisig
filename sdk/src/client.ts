import {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
  SYSVAR_RENT_PUBKEY,
  TransactionInstruction,
  TransactionMessage as Web3TransactionMessage,
  VersionedTransaction,
  AddressLookupTableProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider } from "@coral-xyz/anchor";
import {
  InitializeResult,
  CreateTransactionResult,
  MultisigConfig,
  VaultTransactionData,
  TransactionMessage,
} from "./types";
import {
  deriveMultisigAddress,
  deriveNonceAccount,
  deriveVaultAddress,
  hashMembers,
  sortMembers,
  validateConfig,
  buildMessageFromInstructions,
} from "./utils";

/**
 * Anchor's `Wallet` interface — duplicated locally so the SDK doesn't take a
 * top-level reference to anchor's `Wallet` class. Some bundlers (notably
 * Vite for browser builds) tree-shake `Wallet` away, which used to make the
 * SDK constructor throw "Wallet is not a constructor" at runtime when no
 * wallet was passed. By accepting a structurally-typed wallet here and
 * defaulting to an inline read-only stub, consumers who only use the SDK
 * for queries + ix building never need to import `Wallet` at all.
 */
export interface AnchorWalletLike {
  publicKey: PublicKey;
  signTransaction<T extends Transaction | VersionedTransaction>(
    tx: T
  ): Promise<T>;
  signAllTransactions<T extends Transaction | VersionedTransaction>(
    txs: T[]
  ): Promise<T[]>;
  payer?: Keypair;
}

/**
 * Bump the BorshInstructionCoder's scratch buffer past Anchor's hardcoded
 * 1000-byte allocation (see node_modules/@coral-xyz/anchor/.../coder/borsh/instruction.js
 * — there's a TODO comment from the anchor maintainers about this).
 *
 * For our `create_transaction` ix, message data + many account_keys can
 * exceed 1000 bytes, throwing "encoding overruns Buffer" client-side.
 * Solana's tx-size cap is 1232 bytes total, so 2000 bytes for ix args is
 * safely above any valid input.
 *
 * The patch matches anchor's encode shape: 8-byte sighash discriminator
 * followed by borsh-encoded args. Sighash for global ix `<name>` is
 * `sha256("global:<name>")[..8]`.
 */
function patchIxEncoderBufferSize(program: Program, size: number): void {
  try {
    const ixCoder = (program.coder.instruction as unknown) as {
      ixLayouts?: Map<
        string,
        {
          discriminator: number[];
          layout: { encode: (data: unknown, b: Buffer) => number };
        }
      >;
      encode?: (ixName: string, data: unknown) => Buffer;
    };
    const layouts = ixCoder.ixLayouts;
    if (!ixCoder.encode || !layouts) return;

    ixCoder.encode = (ixName: string, data: unknown): Buffer => {
      const entry = layouts.get(ixName);
      if (!entry) {
        throw new Error(`Unknown instruction: ${ixName}`);
      }
      const buffer = Buffer.alloc(size);
      const len = entry.layout.encode(data, buffer);
      return Buffer.concat([
        Buffer.from(entry.discriminator),
        buffer.subarray(0, len),
      ]);
    };
  } catch {
    // best effort — fall through to anchor's default 1000-byte cap
  }
}

/**
 * Main SDK client for the SSP Solana Multisig program.
 */
export class SolanaMultisigClient {
  private connection: Connection;
  private program: Program;
  private programId: PublicKey;
  private provider: AnchorProvider;

  constructor(
    connection: Connection,
    programId: PublicKey,
    wallet?: AnchorWalletLike
  ) {
    this.connection = connection;
    this.programId = programId;

    // Default to a read-only stub wallet — query-only methods (`deriveAddress`,
    // `getMultisig`, the `build*Instruction` helpers) never ask the provider
    // wallet to sign. Inlining a stub here (instead of `new Wallet(...)` from
    // anchor) means bundlers don't need to keep anchor's `Wallet` class
    // reachable.
    //
    // The stub's signing methods THROW rather than silently return the
    // unsigned tx: the `.rpc()`-flavored methods (`initialize`,
    // `createTransaction`, …) use the provider wallet as fee payer and will
    // ask it to sign. A no-op stub there would produce an unsigned tx that the
    // cluster rejects with a confusing "missing signature" error far from the
    // real cause (constructing the client without a wallet). Throwing here
    // points directly at the fix.
    const stubKeypair = Keypair.generate();
    const throwNoWallet = (): never => {
      throw new Error(
        "SolanaMultisigClient was constructed without a wallet, so it cannot sign transactions. " +
          "Pass a wallet to the constructor for .rpc()-flavored methods (initialize, createTransaction, …), " +
          "or use the explicit instruction-builder methods (build*Instruction) for read-only / external-signing flows."
      );
    };
    const readonlyWallet: AnchorWalletLike = wallet ?? {
      publicKey: stubKeypair.publicKey,
      payer: stubKeypair,
      signTransaction: throwNoWallet,
      signAllTransactions: throwNoWallet,
    };
    this.provider = new AnchorProvider(
      connection,
      readonlyWallet as never,
      { commitment: "confirmed" }
    );

    // Load program IDL (bundled in the SDK)
    const idl = require("./idl/solana_multisig.json");
    this.program = new Program(idl, this.provider);

    // Anchor's BorshInstructionCoder pre-allocates a 1000-byte scratch
    // buffer for ix args (see node_modules/@coral-xyz/anchor/.../coder/borsh/instruction.js).
    // For create_transaction with many account_keys + a fat ix data field
    // (e.g. a real Jupiter swap), 1000 bytes overruns. Solana's tx-size
    // limit is 1232 bytes for the FULL tx — args alone can practically
    // hit ~1100. Bump the scratch buffer to 2000 to safely cover any
    // valid create_transaction proposal.
    patchIxEncoderBufferSize(this.program, 2000);
  }

  /**
   * Derive the deterministic multisig address
   * This can be called by anyone and will always return the same address
   * for the same configuration
   */
  deriveAddress(members: PublicKey[], threshold: number): PublicKey {
    validateConfig(members, threshold);
    const [address] = deriveMultisigAddress(members, threshold, this.programId);
    return address;
  }

  /**
   * Create an Address Lookup Table populated with the multisig's members
   * AND `SystemProgram`, which the init ix references. Including SystemProgram
   * in the ALT lets the V0 compiler route it through the lookup instead of
   * bloating the static account list.
   *
   * Members are stored sorted so all callers produce identical ALT
   * contents for the same member set. The ALT can be reused across many
   * `initialize()` calls if you want sibling multisigs sharing membership.
   *
   * Waits 1 slot (Solana ALT warm-up) AND polls until the ALT account
   * actually reports all addresses are committed before returning.
   *
   * Returns the ALT pubkey, ready to pass to {@link initialize}.
   */
  async createMembersAddressLookupTable(
    members: PublicKey[],
    payer: Keypair
  ): Promise<PublicKey> {
    if (members.length === 0) {
      throw new Error("createMembersAddressLookupTable: members is empty");
    }
    const sortedMembers = sortMembers(members);
    const altAddresses = [...sortedMembers, SystemProgram.programId];

    const recentSlot = await this.connection.getSlot("finalized");
    const [createIx, lookupTableAddress] =
      AddressLookupTableProgram.createLookupTable({
        authority: payer.publicKey,
        payer: payer.publicKey,
        recentSlot,
      });
    const extendIx = AddressLookupTableProgram.extendLookupTable({
      payer: payer.publicKey,
      authority: payer.publicKey,
      lookupTable: lookupTableAddress,
      addresses: altAddresses,
    });

    const tx = new Transaction().add(createIx, extendIx);
    await sendAndConfirmTransaction(this.connection, tx, [payer], {
      commitment: "confirmed",
    });

    // 1-slot warm-up + poll until the ALT account is fully indexed.
    const startSlot = await this.connection.getSlot("processed");
    while ((await this.connection.getSlot("processed")) <= startSlot + 1) {
      await new Promise((r) => setTimeout(r, 200));
    }

    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const acc = await this.connection.getAddressLookupTable(
        lookupTableAddress
      );
      if (
        acc.value &&
        acc.value.state.addresses.length === altAddresses.length
      ) {
        return lookupTableAddress;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(
      `ALT ${lookupTableAddress.toBase58()} did not finalize ${
        altAddresses.length
      } addresses within 10s`
    );
  }

  /**
   * Initialize the multisig at its deterministic PDA. Permissionless —
   * no member signatures required; the PDA address is fully determined
   * by `(sorted_members, threshold)` so initializing with the canonical
   * inputs is the only way to land at the canonical address. Authorization
   * is enforced by the threshold check on `create_transaction` /
   * `approve_transaction` / `execute_transaction`.
   *
   * Built as a V0 transaction so the ALT lookup is honored: members are
   * passed as `remaining_accounts` resolved from the supplied ALT, keeping
   * the on-chain payload to ~1 byte per member instead of 32.
   */
  async initialize(
    members: PublicKey[],
    threshold: number,
    payer: Keypair,
    membersAlt: PublicKey
  ): Promise<InitializeResult> {
    validateConfig(members, threshold);

    const sortedMembers = sortMembers(members);
    const [multisigAddress, bump] = deriveMultisigAddress(
      sortedMembers,
      threshold,
      this.programId
    );

    // Pre-compute member_hash for the program — full 32-byte sha256 of the
    // sorted member pubkeys, also used as the PDA seed.
    const memberHash = hashMembers(sortedMembers);

    const initializeIx = await this.program.methods
      .initializeMultisig(
        Array.from(memberHash),
        threshold,
        sortedMembers.length
      )
      .accounts({
        multisig: multisigAddress,
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        sortedMembers.map((pubkey) => ({
          pubkey,
          isSigner: false,
          isWritable: false,
        }))
      )
      .instruction();

    // Fetch the ALT account so the V0 compiler knows which addresses to
    // de-duplicate from the static account list.
    const altResp = await this.connection.getAddressLookupTable(membersAlt);
    if (!altResp.value) {
      throw new Error(
        `ALT not found at ${membersAlt.toBase58()} — did you call createMembersAddressLookupTable() first?`
      );
    }

    const { blockhash } = await this.connection.getLatestBlockhash();
    const v0Message = new Web3TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: [initializeIx],
    }).compileToV0Message([altResp.value]);

    const tx = new VersionedTransaction(v0Message);
    tx.sign([payer]);
    const txSignature = await this.connection.sendTransaction(tx);
    await this.connection.confirmTransaction(txSignature, "confirmed");

    return {
      signature: txSignature,
      multisigAddress,
      bump,
    };
  }

  /**
   * Pre-fund a multisig address before initialization
   * This demonstrates that funds can be sent to the deterministic address
   * before the multisig is initialized on-chain
   */
  async preFund(
    address: PublicKey,
    amount: number,
    funder: Keypair
  ): Promise<string> {
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: address,
        lamports: amount,
      })
    );

    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [funder],
      { commitment: "confirmed" }
    );

    return signature;
  }

  /**
   * Get multisig account data
   */
  async getMultisig(address: PublicKey): Promise<MultisigConfig | null> {
    try {
      const account = await (this.program.account as any).multisig.fetch(
        address
      );
      return {
        members: account.members as PublicKey[],
        threshold: account.threshold as number,
        transactionIndex: account.transactionIndex as bigint,
        bump: account.bump as number,
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Derive the vault PDA at `vaultIndex` for a given multisig.
   * Vaults are SystemProgram-owned PDAs with no data — they hold SOL + SPL
   * tokens. This is the address users send funds TO.
   */
  deriveVaultAddress(multisigAddress: PublicKey, vaultIndex = 0): PublicKey {
    const [vault] = deriveVaultAddress(
      multisigAddress,
      vaultIndex,
      this.programId
    );
    return vault;
  }

  /**
   * Create a transaction proposal from raw web3.js instructions targeting
   * a specific vault.
   *
   * Builds a V0-style TransactionMessage internally with no ALT support.
   * The vault PDA at `vaultIndex` is forced to be the writable signer at
   * `account_keys[0]` — instructions referencing the vault use index 0.
   *
   * For ALT-aware proposals, use {@link createTransactionFromMessage} and
   * construct the TransactionMessage manually.
   */
  async createTransaction(
    multisigAddress: PublicKey,
    vaultIndex: number,
    instructions: TransactionInstruction[],
    creator: Keypair,
    payer?: Keypair
  ): Promise<CreateTransactionResult> {
    const vaultPda = this.deriveVaultAddress(multisigAddress, vaultIndex);
    const message = buildMessageFromInstructions(vaultPda, instructions);
    return this.createTransactionFromMessage(
      multisigAddress,
      vaultIndex,
      message,
      creator,
      payer
    );
  }

  /**
   * Create a transaction proposal from a pre-built V0-style TransactionMessage.
   *
   * Use this when you need ALT support (set `addressTableLookups` on the
   * message) or need full control over account ordering and signer/writable
   * flags. `account_keys[0]` MUST be the vault PDA at `vaultIndex`.
   */
  async createTransactionFromMessage(
    multisigAddress: PublicKey,
    vaultIndex: number,
    message: TransactionMessage,
    creator: Keypair,
    payer?: Keypair
  ): Promise<CreateTransactionResult> {
    const multisig = await this.getMultisig(multisigAddress);
    if (!multisig) {
      throw new Error("Multisig not found");
    }

    const transactionIndex = multisig.transactionIndex + BigInt(1);
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    const onchainMessage = {
      numSigners: message.numSigners,
      numWritableSigners: message.numWritableSigners,
      numWritableNonSigners: message.numWritableNonSigners,
      accountKeys: message.accountKeys,
      instructions: message.instructions.map((ix) => ({
        programIdIndex: ix.programIdIndex,
        accountIndexes: Buffer.from(ix.accountIndexes),
        data: Buffer.from(ix.data),
      })),
      addressTableLookups: message.addressTableLookups.map((l) => ({
        accountKey: l.accountKey,
        writableIndexes: Buffer.from(l.writableIndexes),
        readonlyIndexes: Buffer.from(l.readonlyIndexes),
      })),
    };

    const rentPayer = payer ?? creator;
    const signers = rentPayer.publicKey.equals(creator.publicKey)
      ? [creator]
      : [creator, rentPayer];

    const tx = await this.program.methods
      .createTransaction(vaultIndex, onchainMessage)
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        creator: creator.publicKey,
        payer: rentPayer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers(signers)
      .rpc();

    return {
      signature: tx,
      transactionAddress,
      transactionIndex,
    };
  }

  /**
   * Approve a transaction proposal
   */
  async approveTransaction(
    multisigAddress: PublicKey,
    transactionIndex: bigint,
    member: Keypair
  ): Promise<string> {
    // Derive transaction PDA
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    const tx = await this.program.methods
      .approveTransaction(new anchor.BN(transactionIndex.toString()))
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        member: member.publicKey,
      })
      .signers([member])
      .rpc();

    return tx;
  }

  /**
   * Execute an approved transaction
   */
  async executeTransaction(
    multisigAddress: PublicKey,
    transactionIndex: bigint,
    executor: Keypair,
    remainingAccounts?: {
      pubkey: PublicKey;
      isSigner: boolean;
      isWritable: boolean;
    }[]
  ): Promise<string> {
    // Derive transaction PDA
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    let txBuilder = this.program.methods
      .executeTransaction(new anchor.BN(transactionIndex.toString()))
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        executor: executor.publicKey,
      })
      .signers([executor]);

    // Add remaining accounts for CPI if provided
    if (remainingAccounts && remainingAccounts.length > 0) {
      txBuilder = txBuilder.remainingAccounts(remainingAccounts);
    }

    const tx = await txBuilder.rpc();

    return tx;
  }

  /**
   * Get VaultTransaction data
   */
  async getTransaction(
    address: PublicKey
  ): Promise<VaultTransactionData | null> {
    try {
      const account = await (
        this.program.account as any
      ).vaultTransaction.fetch(address);
      return {
        multisig: account.multisig as PublicKey,
        transactionIndex: account.transactionIndex as bigint,
        creator: account.creator as PublicKey,
        bump: account.bump as number,
        vaultIndex: account.vaultIndex as number,
        vaultBump: account.vaultBump as number,
        executed: account.executed as boolean,
        approvals: account.approvals as PublicKey[],
        message: account.message as TransactionMessage,
      };
    } catch (e) {
      return null;
    }
  }

  // ==========================================================================
  // Composable instruction builders.
  //
  // These return raw `TransactionInstruction` objects without sending them, so
  // callers can bundle multiple program ixs into a single Solana transaction.
  // The SSP 2-of-2 send flow uses this to combine create/approve/approve/execute
  // (plus optional initialize_multisig + Ed25519 verify on first send) into one
  // atomic, single-broadcast transaction signed by both wallet and key.
  //
  // The high-level methods above (initialize, createTransaction, etc.) wrap
  // these into auto-broadcast helpers for simpler one-off use cases.
  // ==========================================================================

  /**
   * Derive the (transactionAddress, transactionIndex) pair for the proposal
   * that will be created NEXT given the current on-chain transaction_index.
   *
   * Accepts `currentTransactionIndex` as `bigint | number | anchor.BN` —
   * anchor's u64 field deserialization returns BN at runtime even when the
   * SDK's TS type declares bigint. Without normalization, `BN + BigInt(1)`
   * silently produces a STRING via JS coercion (e.g. `BN(1) + 1n` = "11"),
   * which then parses back as decimal 11, producing wildly wrong PDAs and
   * a ConstraintSeeds error on the second send onward. Always coerce via
   * `.toString()` first.
   */
  predictNextTransactionPda(
    multisigAddress: PublicKey,
    currentTransactionIndex: bigint | number | { toString(): string }
  ): { transactionAddress: PublicKey; transactionIndex: bigint } {
    const currentBig = BigInt(currentTransactionIndex.toString());
    const transactionIndex = currentBig + BigInt(1);
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );
    return { transactionAddress, transactionIndex };
  }

  /**
   * Build the `initialize_multisig` instruction (ix only). Permissionless —
   * the only signer required by this ix is `payer` (for rent), which is
   * already the outer tx's fee payer. No member signatures involved.
   */
  async buildInitializeMultisigInstruction(opts: {
    members: PublicKey[];
    threshold: number;
    payer: PublicKey;
  }): Promise<{
    instruction: TransactionInstruction;
    multisigAddress: PublicKey;
    bump: number;
  }> {
    validateConfig(opts.members, opts.threshold);
    const sortedMembers = sortMembers(opts.members);
    const [multisigAddress, bump] = deriveMultisigAddress(
      sortedMembers,
      opts.threshold,
      this.programId
    );
    const memberHash = hashMembers(sortedMembers);
    const instruction = await this.program.methods
      .initializeMultisig(
        Array.from(memberHash),
        opts.threshold,
        sortedMembers.length
      )
      .accounts({
        multisig: multisigAddress,
        payer: opts.payer,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        sortedMembers.map((pubkey) => ({
          pubkey,
          isSigner: false,
          isWritable: false,
        }))
      )
      .instruction();
    return { instruction, multisigAddress, bump };
  }

  /**
   * Build the `create_transaction` instruction (ix only).
   * Returns the next transaction PDA + index alongside the ix.
   *
   * `currentTransactionIndex` should be the on-chain `multisig.transactionIndex`.
   * For first send right after `initialize_multisig`, pass `0n`.
   */
  async buildCreateTransactionInstruction(opts: {
    multisigAddress: PublicKey;
    /**
     * Current on-chain `multisig.transactionIndex`. Accepts bigint, number,
     * or anchor.BN — internally normalized via toString() before arithmetic
     * to dodge the JS coercion footgun where `BN(N) + BigInt(1)` produces
     * a string instead of an arithmetic sum.
     */
    currentTransactionIndex: bigint | number | { toString(): string };
    vaultIndex: number;
    message: TransactionMessage;
    creator: PublicKey;
    /**
     * Account that funds the proposal account's rent and receives the refund
     * on `close_transaction`. Decoupled from `creator` so a paymaster can pay
     * rent while a multisig member authorizes. Defaults to `creator` for
     * backwards-compatible standalone usage.
     */
    payer?: PublicKey;
  }): Promise<{
    instruction: TransactionInstruction;
    transactionAddress: PublicKey;
    transactionIndex: bigint;
  }> {
    const { transactionAddress, transactionIndex } =
      this.predictNextTransactionPda(
        opts.multisigAddress,
        opts.currentTransactionIndex
      );

    const onchainMessage = {
      numSigners: opts.message.numSigners,
      numWritableSigners: opts.message.numWritableSigners,
      numWritableNonSigners: opts.message.numWritableNonSigners,
      accountKeys: opts.message.accountKeys,
      instructions: opts.message.instructions.map((ix) => ({
        programIdIndex: ix.programIdIndex,
        accountIndexes: Buffer.from(ix.accountIndexes),
        data: Buffer.from(ix.data),
      })),
      addressTableLookups: opts.message.addressTableLookups.map((l) => ({
        accountKey: l.accountKey,
        writableIndexes: Buffer.from(l.writableIndexes),
        readonlyIndexes: Buffer.from(l.readonlyIndexes),
      })),
    };

    const instruction = await this.program.methods
      .createTransaction(opts.vaultIndex, onchainMessage)
      .accounts({
        multisig: opts.multisigAddress,
        transaction: transactionAddress,
        creator: opts.creator,
        payer: opts.payer ?? opts.creator,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    return { instruction, transactionAddress, transactionIndex };
  }

  /**
   * Build the `approve_transaction` instruction (ix only).
   * The `member` pubkey must be a Signer in the surrounding tx; the SDK
   * does NOT add any signers — caller controls signing.
   */
  async buildApproveTransactionInstruction(opts: {
    multisigAddress: PublicKey;
    transactionAddress: PublicKey;
    transactionIndex: bigint;
    member: PublicKey;
  }): Promise<TransactionInstruction> {
    return this.program.methods
      .approveTransaction(new anchor.BN(opts.transactionIndex.toString()))
      .accounts({
        multisig: opts.multisigAddress,
        transaction: opts.transactionAddress,
        member: opts.member,
      })
      .instruction();
  }

  /**
   * Build the `execute_transaction` instruction (ix only).
   * `remainingAccounts` must include all accounts referenced by the proposal's
   * `account_keys` in order, with proper isWritable flags.
   */
  async buildExecuteTransactionInstruction(opts: {
    multisigAddress: PublicKey;
    transactionAddress: PublicKey;
    transactionIndex: bigint;
    executor: PublicKey;
    remainingAccounts: Array<{
      pubkey: PublicKey;
      isSigner: boolean;
      isWritable: boolean;
    }>;
  }): Promise<TransactionInstruction> {
    return this.program.methods
      .executeTransaction(new anchor.BN(opts.transactionIndex.toString()))
      .accounts({
        multisig: opts.multisigAddress,
        transaction: opts.transactionAddress,
        executor: opts.executor,
      })
      .remainingAccounts(opts.remainingAccounts)
      .instruction();
  }

  /**
   * Build the `close_transaction` instruction (ix only).
   *
   * Closes an executed proposal, refunding the rent deposit to the account
   * that originally funded it (`transaction.payer`). Typically bundled into
   * the same outer tx as `execute_transaction` so close happens atomically.
   *
   * Constraints:
   *   - the proposal must already be executed (executed = true)
   *   - `payer` must match the proposal's stored payer (signs as refund target)
   */
  async buildCloseTransactionInstruction(opts: {
    multisigAddress: PublicKey;
    transactionAddress: PublicKey;
    transactionIndex: bigint;
    payer: PublicKey;
  }): Promise<TransactionInstruction> {
    return this.program.methods
      .closeTransaction(new anchor.BN(opts.transactionIndex.toString()))
      .accounts({
        multisig: opts.multisigAddress,
        transaction: opts.transactionAddress,
        payer: opts.payer,
      })
      .instruction();
  }

  /**
   * Build the `provision_nonce` instruction (ix only).
   *
   * Creates a durable nonce account at the deterministic address
   * `Pubkey.createWithSeed(multisigPda, "nonce", SystemProgram)`. The
   * address is purely a function of the multisig PDA — paymaster-independent,
   * so re-derivation works across paymaster rotations.
   *
   * Permissionless: anyone can call this; whoever does (`payer`) funds the
   * ~0.00144 SOL rent and becomes the initial nonce authority. For SSP this
   * is always the relay paymaster.
   *
   * One-time per multisig — calling a second time will fail with the System
   * Program rejecting the create (account already exists at the derived
   * address). Callers should treat that as success (nonce already available).
   *
   * ⚠️ RACE-VULNERABLE WHEN SENT STANDALONE. Because the nonce address is
   * deterministic and provisioning is permissionless, an attacker who watches
   * for a fresh `initialize_multisig` can front-run a standalone
   * `provision_nonce` and become the nonce authority. They cannot touch vault
   * funds, but they can grief the durable-nonce flow (advance/withdraw the
   * nonce, refuse to hand authority back). For production, ALWAYS provision
   * the nonce atomically with init via {@link setupMultisigAndNonce}, which
   * bundles both into one transaction so no third party can interleave. Only
   * use the standalone {@link provisionNonce} for testing or when you accept
   * the race.
   */
  async buildProvisionNonceInstruction(opts: {
    multisigAddress: PublicKey;
    payer: PublicKey;
  }): Promise<{
    instruction: TransactionInstruction;
    nonceAccount: PublicKey;
  }> {
    const nonceAccount = await deriveNonceAccount(opts.multisigAddress);
    const instruction = await this.program.methods
      .provisionNonce()
      .accounts({
        multisig: opts.multisigAddress,
        nonceAccount,
        payer: opts.payer,
        recentBlockhashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
        rent: SYSVAR_RENT_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    return { instruction, nonceAccount };
  }

  /**
   * Convenience: provision the nonce account for a multisig in a one-off tx.
   *
   * Idempotent in spirit — if the nonce already exists, this errors out with
   * a System Program "account already in use" error which the caller should
   * treat as a success signal.
   *
   * ⚠️ RACE-VULNERABLE: this standalone path can be front-run between init and
   * provision — see {@link buildProvisionNonceInstruction}. Use
   * {@link setupMultisigAndNonce} in production; reserve this for tests.
   */
  async provisionNonce(opts: {
    multisigAddress: PublicKey;
    payer: Keypair;
  }): Promise<{ signature: string; nonceAccount: PublicKey }> {
    const { instruction, nonceAccount } =
      await this.buildProvisionNonceInstruction({
        multisigAddress: opts.multisigAddress,
        payer: opts.payer.publicKey,
      });
    const tx = new Transaction().add(instruction);
    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [opts.payer],
      { commitment: "confirmed" }
    );
    return { signature, nonceAccount };
  }

  /**
   * One-shot bundled setup: initializes the multisig AND provisions its
   * durable nonce account in a single atomic paymaster-signed tx.
   *
   * This is what the relay paymaster runs via the `POST /v1/sol/setup`
   * endpoint before the user's first send. After this lands, the wallet
   * can immediately build durable-nonce-flow send txes (no blockhash race
   * possible even on the very first user send).
   *
   * Idempotent in spirit: if multisig or nonce already exist, the matching
   * sub-ix fails inside the tx and the bundle aborts — callers can detect
   * via getMultisig / getAccountInfo and skip if already provisioned.
   *
   * Returns the deterministic addresses + the initial nonce value so the
   * caller can immediately use it as `recentBlockhash` in subsequent txes.
   */
  async setupMultisigAndNonce(opts: {
    members: PublicKey[];
    threshold: number;
    payer: Keypair;
    /**
     * Pre-existing ALT containing the sorted member pubkeys + SystemProgram.
     * Required because `initialize_multisig` passes members via
     * `remaining_accounts` and the tx-size budget needs ALT compaction.
     */
    membersAlt: PublicKey;
  }): Promise<{
    signature: string;
    multisigAddress: PublicKey;
    nonceAccount: PublicKey;
    nonceValue: string;
  }> {
    validateConfig(opts.members, opts.threshold);
    const sortedMembers = sortMembers(opts.members);

    const { instruction: initIx, multisigAddress } =
      await this.buildInitializeMultisigInstruction({
        members: sortedMembers,
        threshold: opts.threshold,
        payer: opts.payer.publicKey,
      });
    const { instruction: provisionIx, nonceAccount } =
      await this.buildProvisionNonceInstruction({
        multisigAddress,
        payer: opts.payer.publicKey,
      });

    const altResp = await this.connection.getAddressLookupTable(opts.membersAlt);
    if (!altResp.value) {
      throw new Error(
        `ALT not found at ${opts.membersAlt.toBase58()} — call createMembersAddressLookupTable first`
      );
    }

    const { blockhash } = await this.connection.getLatestBlockhash();
    const v0Msg = new Web3TransactionMessage({
      payerKey: opts.payer.publicKey,
      recentBlockhash: blockhash,
      instructions: [initIx, provisionIx],
    }).compileToV0Message([altResp.value]);

    const tx = new VersionedTransaction(v0Msg);
    tx.sign([opts.payer]);
    const signature = await this.connection.sendTransaction(tx);
    await this.connection.confirmTransaction(signature, "confirmed");

    // Re-fetch the nonce so callers get the live value to use as
    // `recentBlockhash` for their next bundled send.
    const nonceState = await this.connection.getNonceAndContext(nonceAccount);
    if (!nonceState.value) {
      throw new Error(
        `nonce account ${nonceAccount.toBase58()} did not initialize`
      );
    }

    return {
      signature,
      multisigAddress,
      nonceAccount,
      nonceValue: nonceState.value.nonce,
    };
  }

  // ==========================================================================
  // High-level helper for the SSP 2-of-2 single-tx send pattern.
  //
  // SSP exchanges 42 leaf Ed25519 pubkeys per side at pair time; each address
  // index has its own multisig (members = [walletPubkey[i], keyPubkey[i]]).
  // A send for address index `i` becomes a single Solana tx containing:
  //
  //   ix[0] = (optional) initialize_multisig         ← only on first send;
  //                                                   permissionless, no
  //                                                   member sigs required
  //   ix[N] = create_transaction
  //   ix[N+1] = approve_transaction (wallet member)
  //   ix[N+2] = approve_transaction (key member)
  //   ix[N+3] = execute_transaction
  //
  // Both wallet and key partial-sign the resulting tx (each provides its
  // member-level Ed25519 signature). Wallet handles creator + first approve;
  // key handles second approve + execute (or any signer combination — the
  // tx requires both signatures regardless).
  // ==========================================================================
}
