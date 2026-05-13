/**
 * Devnet E2E sanity test for SSP Solana enterprise vaults.
 *
 * Uses the same `build*Instruction` path the SSP enterprise backend uses
 * (NOT the high-level `.rpc()` helpers, which rely on Anchor's stub
 * provider wallet). Funds everything from the local solana keypair to
 * avoid devnet airdrop rate limits.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { SolanaMultisigClient } from "../src";
import {
  deriveVaultAddress,
  deriveMultisigAddress,
  sortMembers,
  buildMessageFromInstructions,
} from "../src/utils";

const PROGRAM_ID = new PublicKey("CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX");
const VAULT_INDEX = 0;
const RPC_URL = "https://api.devnet.solana.com";

function loadLocalKeypair(): Keypair {
  const p = path.join(os.homedir(), ".config", "solana", "id.json");
  const raw = JSON.parse(fs.readFileSync(p, "utf-8")) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

async function sendTx(
  connection: Connection,
  payer: Keypair,
  ixs: TransactionInstruction[],
  signers: Keypair[]
): Promise<string> {
  const tx = new Transaction();
  for (const ix of ixs) tx.add(ix);
  return sendAndConfirmTransaction(connection, tx, [payer, ...signers], {
    commitment: "confirmed",
  });
}

async function transferSol(
  connection: Connection,
  from: Keypair,
  to: PublicKey,
  lamports: number
) {
  return sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: from.publicKey,
        toPubkey: to,
        lamports,
      })
    ),
    [from],
    { commitment: "confirmed" }
  );
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const client = new SolanaMultisigClient(connection, PROGRAM_ID);

  const programAcct = await connection.getAccountInfo(PROGRAM_ID);
  if (!programAcct?.executable) throw new Error("Program not deployed on devnet");
  console.log("✓ Program is live on devnet:", PROGRAM_ID.toBase58());

  const funder = loadLocalKeypair();
  console.log("Funder:", funder.publicKey.toBase58());
  console.log(
    "Funder balance:",
    (await connection.getBalance(funder.publicKey)) / LAMPORTS_PER_SOL,
    "SOL"
  );

  // 3 simulated SSP signers (in real SSP these are HD-derived ed25519 leaves)
  const m1 = Keypair.generate();
  const m2 = Keypair.generate();
  const m3 = Keypair.generate();
  const members = [m1.publicKey, m2.publicKey, m3.publicKey];
  const threshold = 2;

  // -- PDA derivation cross-check --
  const viaClient = client.deriveAddress(members, threshold);
  const [viaDirect] = deriveMultisigAddress(members, threshold, PROGRAM_ID);
  if (!viaClient.equals(viaDirect)) throw new Error("derive mismatch");
  const [viaPreSorted] = deriveMultisigAddress(
    sortMembers(members),
    threshold,
    PROGRAM_ID
  );
  if (!viaPreSorted.equals(viaClient)) throw new Error("sort idempotence broken");
  console.log("✓ Derivation consistent: client = direct = pre-sorted");

  const multisig = viaClient;
  const [vault] = deriveVaultAddress(multisig, VAULT_INDEX, PROGRAM_ID);
  console.log("Multisig PDA:", multisig.toBase58());
  console.log("Vault PDA   :", vault.toBase58());

  // -- Fund the actors --
  await transferSol(connection, funder, m1.publicKey, 0.05 * LAMPORTS_PER_SOL);
  await transferSol(connection, funder, m2.publicKey, 0.05 * LAMPORTS_PER_SOL);
  await transferSol(connection, funder, vault, 0.05 * LAMPORTS_PER_SOL);
  console.log(
    "✓ Funded m1, m2, vault. Vault now has",
    (await connection.getBalance(vault)) / LAMPORTS_PER_SOL,
    "SOL"
  );

  // -- Initialize multisig --
  const membersAlt = await client.createMembersAddressLookupTable(members, m1);
  const initResult = await client.initialize(members, threshold, m1, membersAlt);
  console.log("✓ Init tx:", initResult.signature);
  const multisigAcct = await connection.getAccountInfo(multisig);
  if (!multisigAcct) throw new Error("Multisig not created on-chain");
  console.log(
    "✓ Multisig account on-chain (data len:",
    multisigAcct.data.length,
    "bytes)"
  );

  // -- Build proposal (SystemProgram::transfer from vault) --
  const recipient = Keypair.generate();
  const amount = 0.02 * LAMPORTS_PER_SOL;
  const transferIx = SystemProgram.transfer({
    fromPubkey: vault,
    toPubkey: recipient.publicKey,
    lamports: amount,
  });
  const proposalMessage = buildMessageFromInstructions(vault, [transferIx]);

  const multisigStateBefore = await client.getMultisig(multisig);
  if (!multisigStateBefore) throw new Error("Cannot read multisig state");

  const createResult = await client.buildCreateTransactionInstruction({
    multisigAddress: multisig,
    currentTransactionIndex: multisigStateBefore.transactionIndex,
    vaultIndex: VAULT_INDEX,
    message: proposalMessage,
    creator: m1.publicKey,
  });

  const createSig = await sendTx(
    connection,
    m1,
    [createResult.instruction],
    [] // creator already in payer
  );
  console.log("✓ create_transaction tx:", createSig);
  console.log("✓ proposal index:", createResult.transactionIndex.toString());

  // -- Approve to threshold --
  const approve1Ix = await client.buildApproveTransactionInstruction({
    multisigAddress: multisig,
    transactionAddress: createResult.transactionAddress,
    transactionIndex: createResult.transactionIndex,
    member: m1.publicKey,
  });
  const approve2Ix = await client.buildApproveTransactionInstruction({
    multisigAddress: multisig,
    transactionAddress: createResult.transactionAddress,
    transactionIndex: createResult.transactionIndex,
    member: m2.publicKey,
  });
  await sendTx(connection, m1, [approve1Ix], []);
  console.log("✓ m1 approved");
  await sendTx(connection, m2, [approve2Ix], []);
  console.log("✓ m2 approved (threshold", threshold, "reached)");

  // -- Execute --
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisig,
    transactionAddress: createResult.transactionAddress,
    transactionIndex: createResult.transactionIndex,
    executor: m1.publicKey,
    remainingAccounts: [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });

  const balBefore = await connection.getBalance(recipient.publicKey);
  const execSig = await sendTx(connection, m1, [executeIx], []);
  const balAfter = await connection.getBalance(recipient.publicKey);
  const received = (balAfter - balBefore) / LAMPORTS_PER_SOL;
  console.log("✓ execute tx:", execSig);
  console.log("✓ recipient received:", received, "SOL");
  if (Math.abs(received - 0.02) > 1e-9) {
    throw new Error(`Expected 0.02 SOL, got ${received}`);
  }

  console.log("\n========================================");
  console.log("ALL CHECKS PASSED:");
  console.log("  • Program live on devnet");
  console.log("  • PDA derivation consistent across SDK paths");
  console.log("  • Initialize accepts our derived PDA");
  console.log("  • Build-ix path (enterprise's path) works end-to-end");
  console.log("  • Funds moved from vault via M-of-N approval");
  console.log("========================================");
}

main().catch((err) => {
  console.error("FAILED:", err.message);
  if (err.logs) console.error(err.logs);
  process.exit(1);
});
