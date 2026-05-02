import {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage as Web3TransactionMessage,
  VersionedTransaction,
  AddressLookupTableProgram,
  sendAndConfirmTransaction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import {
  SignatureData,
  InitializeResult,
  CreateTransactionResult,
  MultisigConfig,
  VaultTransactionData,
  TransactionMessage,
} from "./types";
import {
  deriveMultisigAddress,
  deriveVaultAddress,
  createInitSignature,
  createInitializationMessage,
  hashMembers,
  sortMembers,
  validateConfig,
  verifySignature,
  createBatchedEd25519Instruction,
  buildMessageFromInstructions,
} from "./utils";

/**
 * Main SDK client for Truly Self-Initiating Multisig
 */
export class TrulySelfInitiatingMultisigClient {
  private connection: Connection;
  private program: Program;
  private programId: PublicKey;
  private provider: AnchorProvider;

  constructor(connection: Connection, programId: PublicKey, wallet?: Wallet) {
    this.connection = connection;
    this.programId = programId;

    // Create provider
    this.provider = new AnchorProvider(
      connection,
      wallet || new Wallet(Keypair.generate()),
      { commitment: "confirmed" }
    );

    // Load program IDL
    const idl = require("../../target/idl/truly_self_initiating_multisig.json");
    this.program = new Program(idl, this.provider);
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
   * Create an initialization signature (off-chain)
   * Each member must call this with their private key
   */
  createSignature(
    members: PublicKey[],
    threshold: number,
    memberKeypair: Keypair
  ): SignatureData {
    validateConfig(members, threshold);

    // Ensure the keypair is actually a member
    const sortedMembers = sortMembers(members);
    if (!sortedMembers.some((m) => m.equals(memberKeypair.publicKey))) {
      throw new Error("Keypair is not a member of this multisig");
    }

    return createInitSignature(members, threshold, memberKeypair);
  }

  /**
   * Verify signatures (client-side validation before sending to chain)
   */
  verifySignatures(
    members: PublicKey[],
    threshold: number,
    signatures: SignatureData[]
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
      validateConfig(members, threshold);
    } catch (e) {
      errors.push(`Config validation failed: ${(e as Error).message}`);
      return { valid: false, errors };
    }

    // Check we have enough signatures
    if (signatures.length < threshold) {
      errors.push(
        `Insufficient signatures: need ${threshold}, got ${signatures.length}`
      );
    }

    // Verify each signature
    const sortedMembers = sortMembers(members);
    const seenSigners = new Set<string>();

    for (const sig of signatures) {
      // Check signer is a member
      if (!sortedMembers.some((m) => m.equals(sig.signer))) {
        errors.push(`Signer ${sig.signer.toString()} is not a member`);
        continue;
      }

      // Check for duplicates
      const signerStr = sig.signer.toString();
      if (seenSigners.has(signerStr)) {
        errors.push(`Duplicate signature from ${signerStr}`);
        continue;
      }
      seenSigners.add(signerStr);

      // Verify signature
      if (!verifySignature(sig, members, threshold)) {
        errors.push(`Invalid signature from ${signerStr}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Create an Address Lookup Table populated with the multisig's members
   * AND the well-known accounts that the init ix references (`SystemProgram`,
   * instructions sysvar). Including those system accounts in the ALT lets
   * the V0 compiler route them through the lookup instead of bloating the
   * static account list — recovers ~64 bytes that's needed to fit big
   * multisigs (e.g. 7-of-10) under the 1232-byte tx cap.
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
    const altAddresses = [
      ...sortedMembers,
      SystemProgram.programId,
      SYSVAR_INSTRUCTIONS_PUBKEY,
    ];

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
   * Initialize the multisig.
   *
   * The transaction contains:
   *   ix[0] = batched Ed25519 native-program ix verifying every collected
   *           signature over the shared 67-byte init message
   *   ix[1] = our `initialize_multisig` ix; members are passed as
   *           `remaining_accounts` resolved from the supplied ALT, the
   *           pre-computed `member_hash` is the on-chain PDA seed
   *
   * Built as a V0 transaction so the ALT lookup is honored. Members in
   * the ALT keep the on-chain payload to ~1 byte per member instead of 32,
   * letting us fit up to 7 raw signatures in a single tx.
   */
  async initialize(
    members: PublicKey[],
    threshold: number,
    signatures: SignatureData[],
    payer: Keypair,
    membersAlt: PublicKey
  ): Promise<InitializeResult> {
    validateConfig(members, threshold);

    const validation = this.verifySignatures(members, threshold, signatures);
    if (!validation.valid) {
      throw new Error(
        `Signature validation failed:\n${validation.errors.join("\n")}`
      );
    }

    const sortedMembers = sortMembers(members);
    const [multisigAddress, bump] = deriveMultisigAddress(
      sortedMembers,
      threshold,
      this.programId
    );

    // Pre-compute member_hash for the program — must match what's used as
    // PDA seed bytes (first 8 bytes of sha256(sorted_members)).
    const memberHash = hashMembers(sortedMembers);

    const message = createInitializationMessage(members, threshold);
    const ed25519Ix = createBatchedEd25519Instruction(signatures, message);

    const initializeIx = await this.program.methods
      .initializeMultisig(Array.from(memberHash), threshold)
      .accounts({
        multisig: multisigAddress,
        payer: payer.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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
      instructions: [ed25519Ix, initializeIx],
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
    creator: Keypair
  ): Promise<CreateTransactionResult> {
    const vaultPda = this.deriveVaultAddress(multisigAddress, vaultIndex);
    const message = buildMessageFromInstructions(vaultPda, instructions);
    return this.createTransactionFromMessage(
      multisigAddress,
      vaultIndex,
      message,
      creator
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
    creator: Keypair
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

    // Convert message to the on-chain Anchor encoding (numeric arrays for
    // Vec<u8> fields, plain pubkeys for Vec<Pubkey>).
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

    const tx = await this.program.methods
      .createTransaction(vaultIndex, onchainMessage)
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        creator: creator.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([creator])
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
}
