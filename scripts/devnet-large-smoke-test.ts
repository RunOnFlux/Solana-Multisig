/**
 * Devnet large-multisig smoke test — 7-of-10 with ALT-compacted init.
 *
 * This exercises the documented capacity ceiling for single-tx init:
 *   - 10 members
 *   - 7 threshold signatures bundled in one batched Ed25519 ix
 *   - ALT compaction routes member pubkeys + system accounts through ALT
 *     so the outer tx fits under the 1232-byte cap
 *
 *   init 7-of-10 → prefund vault → propose SOL transfer → 7 approvals →
 *   execute → verify
 *
 * Run: yarn ts-node scripts/devnet-large-smoke-test.ts
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
import { TrulySelfInitiatingMultisigClient } from "../sdk/src";

const DEVNET_RPC = "https://api.devnet.solana.com";
const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
);
const DEPLOYER_KEYPAIR_PATH = path.join(os.homedir(), ".config/solana/id.json");

const MEMBER_COUNT = 10;
const THRESHOLD = 7;

const log = (...args: unknown[]) => console.log(...args);
const sol = (lamports: number) => (lamports / LAMPORTS_PER_SOL).toFixed(6);

async function main() {
  const connection = new Connection(DEVNET_RPC, "confirmed");

  const deployerKey = JSON.parse(
    fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")
  );
  const deployer = Keypair.fromSecretKey(Uint8Array.from(deployerKey));
  const wallet = new anchor.Wallet(deployer);
  const client = new TrulySelfInitiatingMultisigClient(
    connection,
    PROGRAM_ID,
    wallet
  );

  log(`=== Devnet ${THRESHOLD}-of-${MEMBER_COUNT} smoke test ===`);
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer:", deployer.publicKey.toBase58());

  const startBalance = await connection.getBalance(deployer.publicKey);
  log("Deployer balance:", sol(startBalance), "SOL");

  // 1. Generate 10 fresh member keypairs
  const members = Array.from({ length: MEMBER_COUNT }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  log(`\n[1] Generated ${MEMBER_COUNT} member keypairs`);

  // 2. Fund each member with 0.02 SOL (covers rent + tx fees)
  const memberFundLamports = 0.02 * LAMPORTS_PER_SOL;
  // Split into two transactions — 10 transfers in one tx is fine, but a
  // smaller batch keeps things simple if we ever bump member count.
  const fundTx = new Transaction();
  for (const m of members) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m.publicKey,
        lamports: memberFundLamports,
      })
    );
  }
  const fundSig = await connection.sendTransaction(fundTx, [deployer]);
  await connection.confirmTransaction(fundSig, "confirmed");
  log(
    `[2] Funded all ${MEMBER_COUNT} members with`,
    sol(memberFundLamports),
    "SOL each"
  );

  // 3. Derive multisig + vault addresses
  const multisigAddress = client.deriveAddress(memberPubkeys, THRESHOLD);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  log("\n[3] Derived multisig:", multisigAddress.toBase58());
  log("    Vault PDA:        ", vaultPda.toBase58());

  // 4. Threshold members sign the init message
  const sigs = members
    .slice(0, THRESHOLD)
    .map((m) => client.createSignature(memberPubkeys, THRESHOLD, m));
  log(`\n[4] Collected ${sigs.length} init signatures`);

  // 5. Create ALT (members + system accounts → routes pubkeys via lookup so
  //    the V0 outer tx stays under 1232 bytes)
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  log("\n[5] ALT created:", alt.toBase58());

  // 6. Init the multisig — this is THE stress test (7 sigs + 10 members
  //    with ALT compaction must fit in a single V0 tx)
  const initResult = await client.initialize(
    memberPubkeys,
    THRESHOLD,
    sigs,
    deployer,
    alt
  );
  log("\n[6] Multisig initialized via ALT-compacted V0 tx");
  log("    sig:", initResult.signature);

  // 7. Prefund the vault
  const vaultFundLamports = 0.01 * LAMPORTS_PER_SOL;
  const prefundTx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: deployer.publicKey,
      toPubkey: vaultPda,
      lamports: vaultFundLamports,
    })
  );
  const prefundSig = await connection.sendTransaction(prefundTx, [deployer]);
  await connection.confirmTransaction(prefundSig, "confirmed");
  const vaultBefore = await connection.getBalance(vaultPda);
  log("\n[7] Vault prefunded —", sol(vaultBefore), "SOL");

  // 8. Create proposal: send 0.005 SOL from vault to a fresh recipient
  const recipient = Keypair.generate();
  const transferLamports = 0.005 * LAMPORTS_PER_SOL;
  const transferIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: recipient.publicKey,
    lamports: transferLamports,
  });
  const createResult = await client.createTransaction(
    multisigAddress,
    0,
    [transferIx],
    members[0]
  );
  log("\n[8] Proposal created at index", createResult.transactionIndex.toString());
  log("    sig:", createResult.signature);
  log("    recipient:", recipient.publicKey.toBase58());

  // 9. Collect THRESHOLD approvals (members 0..6 = 7 of 10)
  log(`\n[9] Collecting ${THRESHOLD} approvals...`);
  for (let i = 0; i < THRESHOLD; i++) {
    const approveSig = await client.approveTransaction(
      multisigAddress,
      createResult.transactionIndex,
      members[i]
    );
    log(`    member[${i}] approved:`, approveSig);
  }

  // 10. Execute
  const remainingAccounts = [
    { pubkey: vaultPda, isSigner: false, isWritable: true },
    { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  const execSig = await client.executeTransaction(
    multisigAddress,
    createResult.transactionIndex,
    deployer,
    remainingAccounts
  );
  log("\n[10] Executed");
  log("     sig:", execSig);

  // 11. Verify
  const vaultAfter = await connection.getBalance(vaultPda);
  const recipientBalance = await connection.getBalance(recipient.publicKey);
  log("\n[11] Verification:");
  log("     vault before:    ", sol(vaultBefore), "SOL");
  log("     vault after:     ", sol(vaultAfter), "SOL");
  log("     recipient got:   ", sol(recipientBalance), "SOL");

  if (recipientBalance !== transferLamports) {
    throw new Error(
      `FAIL: expected recipient to have ${transferLamports} lamports, got ${recipientBalance}`
    );
  }
  if (vaultBefore - vaultAfter !== transferLamports) {
    throw new Error(
      `FAIL: vault delta mismatch — before=${vaultBefore} after=${vaultAfter}`
    );
  }

  const endBalance = await connection.getBalance(deployer.publicKey);
  log(`\n=== ${THRESHOLD}-OF-${MEMBER_COUNT} SMOKE TEST PASSED ===`);
  log("Total SOL spent:", sol(startBalance - endBalance));
  log("Devnet program handles maximum-config single-tx init via ALT.");
  log("\nReproducible artifacts:");
  log("  Multisig:        ", multisigAddress.toBase58());
  log("  Vault PDA:       ", vaultPda.toBase58());
  log("  ALT:             ", alt.toBase58());
  log("  Init tx:         ", initResult.signature);
  log("  Execute tx:      ", execSig);
}

main().catch((err) => {
  console.error("\n!!! LARGE SMOKE TEST FAILED:");
  console.error(err);
  process.exit(1);
});
