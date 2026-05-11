/**
 * Devnet smoke test — bundled FIRST send with init + provision_nonce in
 * one V0 tx.
 *
 * This mirrors what the SSP wallet does on the very first SOL send from a
 * never-used vault. The outer tx contains:
 *
 *   ix[0] = initialize_multisig  (permissionless)
 *   ix[1] = provision_nonce      (permissionless)
 *   ix[2] = create_transaction   (creator + payer signers)
 *   ix[3] = approve_transaction  (wallet member)
 *   ix[4] = approve_transaction  (key member)
 *   ix[5] = execute_transaction
 *   ix[6] = close_transaction
 *
 * recentBlockhash is a regular blockhash for THIS tx (the nonce doesn't
 * exist yet — we're creating it). The wallet builds + signs + sends
 * immediately so there's no human-loop delay to race the blockhash.
 *
 * Verifies:
 *   - The tx fits under Solana's 1232-byte cap with all 7 ixs
 *   - All steps land atomically in one tx
 *   - Post-send the nonce account exists and is ready for subsequent sends
 *
 * Run: yarn ts-node scripts/devnet-first-send-bundled-test.ts
 */
import * as anchor from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  SolanaMultisigClient,
  deriveMultisigAddress,
  deriveNonceAccount,
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

async function main() {
  const connection = new Connection(DEVNET_RPC, "confirmed");
  const deployerKey = JSON.parse(
    fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")
  );
  const deployer = Keypair.fromSecretKey(Uint8Array.from(deployerKey));
  const wallet = new anchor.Wallet(deployer);
  const client = new SolanaMultisigClient(connection, PROGRAM_ID, wallet);

  log("=== Devnet bundled-first-send smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Paymaster:", deployer.publicKey.toBase58());

  // Always start from a fresh multisig — that's the point of "first send".
  const walletMember = Keypair.generate();
  const keyMember = Keypair.generate();
  log("\n[1] Fresh members:");
  log("    wallet leaf:", walletMember.publicKey.toBase58());
  log("    key leaf:   ", keyMember.publicKey.toBase58());

  // Fund leaves (signers of approve txes).
  const fundTx = new Transaction();
  for (const m of [walletMember.publicKey, keyMember.publicKey]) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m,
        lamports: 0.005 * LAMPORTS_PER_SOL,
      })
    );
  }
  await connection.confirmTransaction(
    await connection.sendTransaction(fundTx, [deployer]),
    "confirmed"
  );
  log("[2] Leaves funded");

  const sortedMembers = sortMembers([
    walletMember.publicKey,
    keyMember.publicKey,
  ]);
  const [multisigPda] = deriveMultisigAddress(sortedMembers, 2, PROGRAM_ID);
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);
  const nonceAccount = await deriveNonceAccount(multisigPda);
  log("[3] Multisig PDA:  ", multisigPda.toBase58());
  log("    Vault PDA:     ", vaultPda.toBase58());
  log("    Nonce derived: ", nonceAccount.toBase58());

  // Confirm we're truly on a fresh multisig.
  if (await client.getMultisig(multisigPda)) {
    throw new Error("multisig already exists — test needs fresh keys");
  }
  if (await connection.getAccountInfo(nonceAccount)) {
    throw new Error("nonce account already exists — test needs fresh keys");
  }
  log("[4] Confirmed: multisig + nonce both pristine (this IS a first send)");

  // Pre-fund the vault.
  const prefundTx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: deployer.publicKey,
      toPubkey: vaultPda,
      lamports: 0.01 * LAMPORTS_PER_SOL,
    })
  );
  await connection.confirmTransaction(
    await connection.sendTransaction(prefundTx, [deployer]),
    "confirmed"
  );
  log("[5] Vault prefunded");

  // ALT with members + SystemProgram (and we'll also want nonce account in
  // there for size compactness, but for first-send the nonce account doesn't
  // exist yet so we can't put a not-yet-created address in an ALT).
  const alt = await client.createMembersAddressLookupTable(
    sortedMembers,
    deployer
  );
  log("[6] ALT created:", alt.toBase58());

  // Build all 7 inner instructions.
  const recipient = Keypair.generate().publicKey;
  const transferLamports = BigInt(0.005 * LAMPORTS_PER_SOL);
  const reimburseLamports = BigInt(0.001 * LAMPORTS_PER_SOL);

  const transferIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: recipient,
    lamports: transferLamports,
  });
  const reimburseIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: deployer.publicKey,
    lamports: reimburseLamports,
  });
  const proposalMessage = {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 2,
    accountKeys: [
      vaultPda,
      recipient,
      deployer.publicKey,
      SystemProgram.programId,
    ],
    instructions: [
      {
        programIdIndex: 3,
        accountIndexes: new Uint8Array([0, 1]),
        data: new Uint8Array(transferIx.data),
      },
      {
        programIdIndex: 3,
        accountIndexes: new Uint8Array([0, 2]),
        data: new Uint8Array(reimburseIx.data),
      },
    ],
    addressTableLookups: [],
  };

  const { instruction: initIx } =
    await client.buildInitializeMultisigInstruction({
      members: sortedMembers,
      threshold: 2,
      payer: deployer.publicKey,
    });
  const { instruction: provisionIx } =
    await client.buildProvisionNonceInstruction({
      multisigAddress: multisigPda,
      payer: deployer.publicKey,
    });
  const {
    instruction: createIx,
    transactionAddress,
    transactionIndex,
  } = await client.buildCreateTransactionInstruction({
    multisigAddress: multisigPda,
    currentTransactionIndex: BigInt(0),
    vaultIndex: 0,
    message: proposalMessage,
    creator: walletMember.publicKey,
    payer: deployer.publicKey,
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
      { pubkey: deployer.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    payer: deployer.publicKey,
  });

  const altResp = await connection.getAddressLookupTable(alt);
  if (!altResp.value) throw new Error("ALT not found");

  const { blockhash } = await connection.getLatestBlockhash();
  const v0Msg = new TransactionMessage({
    payerKey: deployer.publicKey,
    recentBlockhash: blockhash,
    instructions: [
      initIx,
      provisionIx,
      createIx,
      approveWallet,
      approveKey,
      executeIx,
      closeIx,
    ],
  }).compileToV0Message([altResp.value]);

  const tx = new VersionedTransaction(v0Msg);
  tx.sign([deployer, walletMember, keyMember]);

  const serialized = tx.serialize();
  log(
    `\n[7] Bundled first-send tx built. Size: ${serialized.length} bytes (cap: 1232)`
  );
  if (serialized.length > 1232) {
    throw new Error(`tx exceeds 1232-byte cap: ${serialized.length}`);
  }

  const sig = await connection.sendRawTransaction(serialized, {
    skipPreflight: false,
  });
  await connection.confirmTransaction(sig, "confirmed");
  log("    ✅ landed:", sig);

  // Verify all atomic side-effects.
  const multisigState = await client.getMultisig(multisigPda);
  if (!multisigState) throw new Error("multisig not initialized");
  log("[8] ✅ multisig initialized");

  const nonceInfo = await connection.getAccountInfo(nonceAccount);
  if (!nonceInfo) throw new Error("nonce account not provisioned");
  log("    ✅ nonce account provisioned");

  const recipientBalance = await connection.getBalance(recipient);
  if (BigInt(recipientBalance) !== transferLamports) {
    throw new Error(
      `recipient balance ${recipientBalance} != ${transferLamports}`
    );
  }
  log(`    ✅ recipient received ${sol(recipientBalance)} SOL`);

  log("\n=== BUNDLED FIRST-SEND TEST PASSED ===");
  log(
    `7 ixs in one tx: init + provision_nonce + create + approve×2 + execute + close`
  );
  log(`Tx size: ${serialized.length} bytes (cap: 1232)`);
  log(`After this tx: multisig + nonce both exist, ready for subsequent sends`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
