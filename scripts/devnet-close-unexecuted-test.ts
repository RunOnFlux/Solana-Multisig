/**
 * Devnet close-unexecuted test — proves the relaxed `close_transaction`
 * (payer may reclaim a NON-executed proposal's rent) works on the deployed
 * devnet program. This is the §10 change from SOLANA_SPLIT_APPROVAL_PLAN.md:
 * split-flow proposals land `create_transaction` at the first signature, so
 * rejected/expired proposals leave an unexecuted on-chain account whose rent
 * the paymaster must be able to reclaim.
 *
 *   init 2-of-3 multisig → propose SOL transfer (deployer pays rent) →
 *   ONE approval (below threshold) → close WITHOUT execute →
 *   assert rent refunded to payer + account gone + non-payer close rejected
 *
 * Run: yarn ts-node scripts/devnet-close-unexecuted-test.ts
 */
import * as anchor from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { SolanaMultisigClient } from "../sdk/src";

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

  log("=== Devnet close-unexecuted (rent reclaim) test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer (payer):", deployer.publicKey.toBase58());

  // 1. Fresh 2-of-3 multisig — creator member needs a little SOL for tx fees.
  const members = Array.from({ length: 3 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 2;
  const fundTx = new Transaction();
  for (const m of members.slice(0, 2)) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m.publicKey,
        lamports: 0.01 * LAMPORTS_PER_SOL,
      })
    );
  }
  const fundSig = await connection.sendTransaction(fundTx, [deployer]);
  await connection.confirmTransaction(fundSig, "confirmed");
  log("\n[1] Funded 2 member keypairs (creator + approver)");

  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  const initResult = await client.initialize(
    memberPubkeys,
    threshold,
    deployer,
    alt
  );
  log("\n[2] 2-of-3 multisig initialized:", multisigAddress.toBase58());
  log("    sig:", initResult.signature);

  // 2. Create a proposal (member creates, deployer pays rent — the SSP
  //    paymaster pattern). Vault is intentionally NOT funded: creation
  //    doesn't check balances, and this proposal will never execute.
  const recipient = Keypair.generate();
  const transferIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: recipient.publicKey,
    lamports: 0.001 * LAMPORTS_PER_SOL,
  });
  const createResult = await client.createTransaction(
    multisigAddress,
    0,
    [transferIx],
    members[0],
    deployer
  );
  log(
    "\n[3] Proposal created at index",
    createResult.transactionIndex.toString()
  );
  log("    sig:", createResult.signature);

  // 3. ONE approval — below the 2-of-3 threshold (mirrors an abandoned
  //    split-flow proposal with partial approvals landed).
  const approveSig = await client.approveTransaction(
    multisigAddress,
    createResult.transactionIndex,
    members[1]
  );
  log("\n[4] One approval landed (1 < threshold 2):", approveSig);

  const proposalAcc = await connection.getAccountInfo(
    createResult.transactionAddress
  );
  if (!proposalAcc) throw new Error("proposal account missing after create");
  const rentLocked = proposalAcc.lamports;
  log("    proposal rent locked:", sol(rentLocked), "SOL");

  // 4. Negative check first: a NON-payer (the creator member) must NOT be
  //    able to close — has_one = payer gate.
  let nonPayerRejected = false;
  try {
    const badCloseIx = await client.buildCloseTransactionInstruction({
      multisigAddress,
      transactionAddress: createResult.transactionAddress,
      transactionIndex: createResult.transactionIndex,
      payer: members[0].publicKey,
    });
    const badTx = new Transaction().add(badCloseIx);
    badTx.feePayer = members[0].publicKey;
    badTx.recentBlockhash = (
      await connection.getLatestBlockhash("confirmed")
    ).blockhash;
    badTx.sign(members[0]);
    await connection.sendRawTransaction(badTx.serialize());
  } catch {
    nonPayerRejected = true;
  }
  if (!nonPayerRejected) {
    throw new Error("FAIL: non-payer was able to close the proposal");
  }
  log("\n[5] Non-payer close correctly REJECTED (has_one = payer)");

  // 5. Payer reclaims the UNEXECUTED proposal — the new §10 behavior.
  const payerBefore = await connection.getBalance(deployer.publicKey);
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress,
    transactionAddress: createResult.transactionAddress,
    transactionIndex: createResult.transactionIndex,
    payer: deployer.publicKey,
  });
  const closeTx = new Transaction().add(closeIx);
  closeTx.feePayer = deployer.publicKey;
  closeTx.recentBlockhash = (
    await connection.getLatestBlockhash("confirmed")
  ).blockhash;
  closeTx.sign(deployer);
  const closeSig = await connection.sendRawTransaction(closeTx.serialize());
  await connection.confirmTransaction(closeSig, "confirmed");
  log("\n[6] Payer closed the UNEXECUTED proposal:", closeSig);

  const payerAfter = await connection.getBalance(deployer.publicKey);
  const closedAcc = await connection.getAccountInfo(
    createResult.transactionAddress
  );
  const refunded = payerAfter - payerBefore;
  log("    rent refunded (net of fee):", sol(refunded), "SOL");
  log("    proposal account after close:", closedAcc === null ? "GONE" : "STILL EXISTS");

  if (closedAcc !== null) {
    throw new Error("FAIL: proposal account still exists after close");
  }
  if (refunded < rentLocked * 0.9) {
    throw new Error(
      `FAIL: refund ${sol(refunded)} SOL is less than ~rent ${sol(rentLocked)} SOL`
    );
  }

  log(
    "\n✅ PASS — payer reclaimed",
    sol(rentLocked),
    "SOL rent from an unexecuted (partially-approved) proposal on devnet"
  );
}

main().catch((e) => {
  console.error("❌ FAIL:", e);
  process.exit(1);
});
