/**
 * Devnet smoke test — bundled single-tx send.
 *
 * ⚠️  LEGACY PATTERN — NOT the current SSP wallet flow.
 *
 * The current SSP wallet:
 *   1. Calls relay's POST /v1/sol/setup ONCE per vault (paymaster does
 *      init + provision_nonce as its own tx)
 *   2. Builds the actual send tx using the durable nonce
 *
 * That separated flow is bullet-proof against the 60s blockhash race
 * (durable nonce never expires). See `devnet-setup-endpoint-flow-test.ts`
 * for the current flow's full coverage.
 *
 * This test is retained as documentation that the on-chain program STILL
 * supports the bundled `init + create + approve×2 + execute + close`
 * pattern in one tx — useful for advanced integrators who want to skip
 * the setup endpoint and build everything bundled (at the cost of having
 * to use a regular blockhash, which races against the 60s window if there
 * is any human-loop delay).
 *
 *   ix[0] = initialize_multisig          (only on first send; permissionless)
 *   ix[1] = create_transaction           (proposal authoring)
 *   ix[2] = approve_transaction (member0)
 *   ix[3] = approve_transaction (member1)
 *   ix[4] = execute_transaction
 *   ix[5] = close_transaction            (rent refund to paymaster)
 *
 * Run: yarn ts-node scripts/devnet-bundled-singletx-test.ts
 */
import * as anchor from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  SolanaMultisigClient,
  deriveMultisigAddress,
  deriveVaultAddress,
  sortMembers,
} from "../sdk/src";

const DEVNET_RPC = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
);
const DEPLOYER_KEYPAIR_PATH = path.join(os.homedir(), ".config/solana/id.json");

const log = (...args: unknown[]) => console.log(...args);
const sol = (lamports: number) => (lamports / LAMPORTS_PER_SOL).toFixed(6);

/**
 * Build, sign, and broadcast a bundled single-tx send.
 *
 * Returns the broadcast signature and the serialized tx size so the caller
 * can confirm it fit under Solana's 1232-byte cap.
 */
async function bundledSend(opts: {
  connection: Connection;
  client: SolanaMultisigClient;
  walletMember: Keypair;
  keyMember: Keypair;
  paymaster: Keypair;
  recipient: PublicKey;
  amountLamports: bigint;
  paymasterFeeLamports: bigint;
  /** When true, prepend initialize_multisig at ix[0]. */
  includeInit: boolean;
  /** Provide the on-chain transaction index (0 for first send post-init). */
  currentTransactionIndex: bigint;
  /** Provide the ALT containing member pubkeys + SystemProgram. */
  alt: PublicKey;
}): Promise<{ signature: string; txSize: number }> {
  const {
    connection,
    client,
    walletMember,
    keyMember,
    paymaster,
    recipient,
    amountLamports,
    paymasterFeeLamports,
    includeInit,
    currentTransactionIndex,
    alt,
  } = opts;

  const members = [walletMember.publicKey, keyMember.publicKey];
  const threshold = 2;
  const sortedMembers = sortMembers(members);
  const [multisigPda] = deriveMultisigAddress(
    sortedMembers,
    threshold,
    PROGRAM_ID
  );
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);

  // Inner proposal message: vault → recipient + vault → paymaster reimbursement.
  // account_keys order must be: writable_signers, readonly_signers,
  // writable_non_signers, readonly_non_signers — see lib.rs:836 convention.
  const transferIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: recipient,
    lamports: amountLamports,
  });
  const reimburseIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: paymaster.publicKey,
    lamports: paymasterFeeLamports,
  });
  const proposalMessage = {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 2,
    accountKeys: [vaultPda, recipient, paymaster.publicKey, SystemProgram.programId],
    instructions: [
      {
        programIdIndex: 3, // SystemProgram
        accountIndexes: new Uint8Array([0, 1]), // [vault, recipient]
        data: new Uint8Array(transferIx.data),
      },
      {
        programIdIndex: 3,
        accountIndexes: new Uint8Array([0, 2]), // [vault, paymaster]
        data: new Uint8Array(reimburseIx.data),
      },
    ],
    addressTableLookups: [],
  };

  // Build all the inner ixes that go into the outer tx.
  const initIxs: TransactionInstruction[] = [];
  if (includeInit) {
    const { instruction: initIx } = await client.buildInitializeMultisigInstruction({
      members: sortedMembers,
      threshold,
      payer: paymaster.publicKey,
    });
    initIxs.push(initIx);
  }

  const { instruction: createIx, transactionAddress, transactionIndex } =
    await client.buildCreateTransactionInstruction({
      multisigAddress: multisigPda,
      currentTransactionIndex,
      vaultIndex: 0,
      message: proposalMessage,
      creator: walletMember.publicKey,
      payer: paymaster.publicKey,
    });
  const approveWallet = await client.buildApproveTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    member: walletMember.publicKey,
  });
  const approveKey = await client.buildApproveTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    member: keyMember.publicKey,
  });
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    executor: walletMember.publicKey,
    remainingAccounts: [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
      { pubkey: paymaster.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    payer: paymaster.publicKey,
  });

  const altResp = await connection.getAddressLookupTable(alt);
  if (!altResp.value) throw new Error(`ALT ${alt.toBase58()} not found`);

  const { blockhash } = await connection.getLatestBlockhash();
  const v0Msg = new TransactionMessage({
    payerKey: paymaster.publicKey,
    recentBlockhash: blockhash,
    instructions: [...initIxs, createIx, approveWallet, approveKey, executeIx, closeIx],
  }).compileToV0Message([altResp.value]);

  const tx = new VersionedTransaction(v0Msg);
  tx.sign([paymaster, walletMember, keyMember]);

  const serialized = tx.serialize();
  const txSize = serialized.length;

  const sig = await connection.sendRawTransaction(serialized, {
    skipPreflight: false,
  });
  await connection.confirmTransaction(sig, "confirmed");

  return { signature: sig, txSize };
}

async function main() {
  const connection = new Connection(DEVNET_RPC, "confirmed");

  const deployerKey = JSON.parse(
    fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")
  );
  const deployer = Keypair.fromSecretKey(Uint8Array.from(deployerKey));
  const wallet = new anchor.Wallet(deployer);
  const client = new SolanaMultisigClient(connection, PROGRAM_ID, wallet);

  log("=== Devnet bundled single-tx smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer (paymaster):", deployer.publicKey.toBase58());

  // 2-of-2 multisig with two fresh leaf keypairs (mirrors the SSP wallet/key pair)
  const walletMember = Keypair.generate();
  const keyMember = Keypair.generate();
  log("\n[1] Members generated");
  log("    wallet leaf:", walletMember.publicKey.toBase58());
  log("    key leaf:   ", keyMember.publicKey.toBase58());

  // Fund the leaves — only because approve_transaction needs them as
  // tx-level signers (Solana requires every signer to exist on-chain even
  // if they're not paying fees). 0.002 SOL is plenty.
  const fundTx = new Transaction();
  for (const m of [walletMember.publicKey, keyMember.publicKey]) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m,
        lamports: 0.002 * LAMPORTS_PER_SOL,
      })
    );
  }
  const fundSig = await connection.sendTransaction(fundTx, [deployer]);
  await connection.confirmTransaction(fundSig, "confirmed");
  log("[2] Leaves funded");

  // Pre-create the ALT (in production the SSP relay creates one per address-index
  // and reuses across sends).
  const alt = await client.createMembersAddressLookupTable(
    [walletMember.publicKey, keyMember.publicKey],
    deployer
  );
  log("[3] ALT created:", alt.toBase58());

  // Derive + pre-fund the vault.
  const sortedMembers = sortMembers([walletMember.publicKey, keyMember.publicKey]);
  const [multisigPda] = deriveMultisigAddress(sortedMembers, 2, PROGRAM_ID);
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);
  log("[4] Multisig PDA:", multisigPda.toBase58());
  log("    Vault PDA:   ", vaultPda.toBase58());

  const prefundTx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: deployer.publicKey,
      toPubkey: vaultPda,
      lamports: 0.02 * LAMPORTS_PER_SOL,
    })
  );
  const prefundSig = await connection.sendTransaction(prefundTx, [deployer]);
  await connection.confirmTransaction(prefundSig, "confirmed");
  log("[5] Vault prefunded with 0.02 SOL");

  const recipient = Keypair.generate().publicKey;
  log("[6] Recipient:", recipient.toBase58());

  // ============================================================
  // FIRST SEND — init bundled into the same tx
  // ============================================================
  log("\n--- FIRST SEND (bundled init) ---");
  const first = await bundledSend({
    connection,
    client,
    walletMember,
    keyMember,
    paymaster: deployer,
    recipient,
    amountLamports: BigInt(0.005 * LAMPORTS_PER_SOL),
    paymasterFeeLamports: BigInt(0.001 * LAMPORTS_PER_SOL),
    includeInit: true,
    currentTransactionIndex: BigInt(0),
    alt,
  });
  log("    ✅ sig:", first.signature);
  log(`    tx size: ${first.txSize} bytes (cap: 1232) — ${first.txSize <= 1232 ? "fits" : "OVER CAP"}`);

  // Verify the multisig got initialized.
  const msState = await client.getMultisig(multisigPda);
  if (!msState) throw new Error("multisig not initialized after bundled send");
  if (msState.threshold !== 2) throw new Error("wrong threshold stored");
  if (msState.members.length !== 2) throw new Error("wrong member count stored");
  log("    ✅ on-chain multisig state: 2-of-2, members canonical");

  // ============================================================
  // SUBSEQUENT SEND — no init ix; just create + 2 approvals + execute + close
  // ============================================================
  log("\n--- SUBSEQUENT SEND (no init) ---");
  const second = await bundledSend({
    connection,
    client,
    walletMember,
    keyMember,
    paymaster: deployer,
    recipient,
    amountLamports: BigInt(0.003 * LAMPORTS_PER_SOL),
    paymasterFeeLamports: BigInt(0.001 * LAMPORTS_PER_SOL),
    includeInit: false,
    currentTransactionIndex: BigInt(msState.transactionIndex.toString()),
    alt,
  });
  log("    ✅ sig:", second.signature);
  log(`    tx size: ${second.txSize} bytes (cap: 1232) — ${second.txSize <= 1232 ? "fits" : "OVER CAP"}`);

  // Verify recipient got both sends.
  const recipientBalance = await connection.getBalance(recipient);
  log(`\n[7] Recipient balance: ${sol(recipientBalance)} SOL (expected 0.008)`);

  if (recipientBalance < 0.008 * LAMPORTS_PER_SOL) {
    throw new Error("recipient did not receive both sends");
  }

  log("\n=== BUNDLED SINGLE-TX TEST PASSED ===");
  log("Bundled flow (consumer 2-of-2) works end-to-end on devnet.");
  log(`First send (with init):  ${first.txSize} bytes`);
  log(`Subsequent send:         ${second.txSize} bytes`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
