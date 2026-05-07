/**
 * Devnet smoke test — proves the deployed program works end-to-end.
 *
 *   init 3-of-5 multisig → prefund vault → propose SOL transfer →
 *   3 approvals → execute → verify recipient received funds
 *
 * Run: yarn ts-node scripts/devnet-smoke-test.ts
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

  log("=== Devnet smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer:", deployer.publicKey.toBase58());

  const startBalance = await connection.getBalance(deployer.publicKey);
  log("Deployer balance:", sol(startBalance), "SOL");

  // 1. Generate 5 fresh member keypairs
  const members = Array.from({ length: 5 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 3;
  log("\n[1] Generated 5 member keypairs");
  members.forEach((m, i) => log(`    [${i}]`, m.publicKey.toBase58()));

  // 2. Fund each member with 0.02 SOL — covers tx fees plus the
  //    creator's rent-exempt deposit on the transaction PDA (~0.007 SOL)
  const memberFundLamports = 0.02 * LAMPORTS_PER_SOL;
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
  log("\n[2] Funded each member with", sol(memberFundLamports), "SOL");
  log("    sig:", fundSig);

  // 3. Derive multisig + vault addresses
  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  log("\n[3] Derived multisig:", multisigAddress.toBase58());
  log("    Vault PDA:        ", vaultPda.toBase58());

  // 4. Each of `threshold` members signs the init message
  const sigs = members
    .slice(0, threshold)
    .map((m) => client.createSignature(memberPubkeys, threshold, m));
  log("\n[4] Collected", sigs.length, "init signatures");

  // 5. Create ALT (needed by SDK init path)
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  log("\n[5] ALT created:", alt.toBase58());

  // 6. Initialize the multisig on-chain
  const initResult = await client.initialize(
    memberPubkeys,
    threshold,
    sigs,
    deployer,
    alt
  );
  log("\n[6] Multisig initialized");
  log("    sig:", initResult.signature);

  // 7. Prefund the vault with 0.01 SOL
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

  // 9. Threshold approvals
  log("\n[9] Collecting approvals...");
  for (let i = 0; i < threshold; i++) {
    const approveSig = await client.approveTransaction(
      multisigAddress,
      createResult.transactionIndex,
      members[i]
    );
    log(`    member[${i}] approved:`, approveSig);
  }

  // 10. Execute (deployer is the executor — anyone can finalize an approved proposal)
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
      `FAIL: vault delta mismatch — before=${vaultBefore} after=${vaultAfter} delta=${
        vaultBefore - vaultAfter
      } expected=${transferLamports}`
    );
  }

  const endBalance = await connection.getBalance(deployer.publicKey);
  log("\n=== SMOKE TEST PASSED ===");
  log("Total SOL spent:", sol(startBalance - endBalance));
  log("Devnet program is functional end-to-end.");
}

main().catch((err) => {
  console.error("\n!!! SMOKE TEST FAILED:");
  console.error(err);
  process.exit(1);
});
