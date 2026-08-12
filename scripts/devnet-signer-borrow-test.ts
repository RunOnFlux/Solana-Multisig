/**
 * Devnet security test — proves the deployed program rejects the
 * paymaster signer-borrow attack (pre-mainnet audit finding).
 *
 * THE ATTACK. `execute_transaction` derives each CPI account's is_signer flag
 * from the proposal's stored header (`is_signer = index < num_signers`). The
 * only signature the program itself supplies is the vault PDA's, via
 * invoke_signed. Any OTHER account marked as a signer therefore borrows the
 * top-level signature of whoever signs the outer execute tx — in the SSP model
 * the relay paymaster, which is the fee payer. An attacker could register their
 * own permissionless 1-of-1 multisig, propose
 * `SystemProgram::transfer { from: paymaster, to: attacker }` with the paymaster
 * in a signer slot, self-approve, and have the relay sponsor execution —
 * draining the paymaster hot wallet. Vault custody was never reachable this way
 * (that stays gated by the M-of-N threshold check), but the paymaster was.
 *
 * THE FIX. `create_transaction` now requires `num_signers == 1`, so the vault
 * PDA is the only account that can ever be a signer in an executed CPI. This
 * script asserts the DEPLOYED program enforces it: a num_signers=2 proposal
 * must be rejected at create time, while an ordinary num_signers=1 proposal
 * from the same multisig still succeeds (proving the guard is precise, not a
 * blanket break).
 *
 * Run: yarn ts-node scripts/devnet-signer-borrow-test.ts
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

async function main() {
  const connection = new Connection(DEVNET_RPC, "confirmed");
  const deployer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")))
  );
  const wallet = new anchor.Wallet(deployer);
  const client = new SolanaMultisigClient(connection, PROGRAM_ID, wallet);

  log("=== Devnet signer-borrow (paymaster drain) security test ===");
  log("Program:", PROGRAM_ID.toBase58());

  // Attacker-controlled 2-of-2 (any member set works — init is permissionless).
  const members = Array.from({ length: 2 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 2;

  const fundTx = new Transaction();
  for (const m of members) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m.publicKey,
        lamports: 0.02 * LAMPORTS_PER_SOL,
      })
    );
  }
  await connection.confirmTransaction(
    await connection.sendTransaction(fundTx, [deployer]),
    "confirmed"
  );

  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  await client.initialize(memberPubkeys, threshold, deployer, alt);
  log("\n[1] Attacker multisig initialized:", multisigAddress.toBase58());
  log("    vault:", vaultPda.toBase58());

  // Stand-in for the relay paymaster: the account whose outer-tx signature the
  // attacker wants the inner CPI to borrow.
  const paymaster = deployer.publicKey;
  const attacker = Keypair.generate().publicKey;

  // ── Attack: mark the paymaster as a second signer and transfer FROM it ──
  const drainData = Buffer.alloc(12);
  drainData.writeUInt32LE(2, 0); // SystemInstruction::Transfer
  drainData.writeBigUInt64LE(BigInt(1_000_000_000), 4); // 1 SOL out of the paymaster

  const maliciousMessage = {
    numSigners: 2, // ILLEGAL: vault + paymaster
    numWritableSigners: 2,
    numWritableNonSigners: 1,
    accountKeys: [vaultPda, paymaster, attacker, SystemProgram.programId],
    instructions: [
      {
        programIdIndex: 3,
        accountIndexes: Buffer.from([1, 2]), // from paymaster → to attacker
        data: drainData,
      },
    ],
    addressTableLookups: [],
  };

  log("\n[2] Attempting signer-borrow proposal (num_signers=2)...");
  log("    inner ix: SystemProgram::transfer 1 SOL FROM paymaster TO attacker");

  let rejected = false;
  let errText = "";
  try {
    await client.createTransactionFromMessage(
      multisigAddress,
      0,
      maliciousMessage as never,
      members[0],
      deployer
    );
  } catch (e) {
    rejected = true;
    errText = String(e);
  }

  if (!rejected) {
    log("\n❌ FAIL — the deployed program ACCEPTED a num_signers=2 proposal.");
    log("   The paymaster is drainable. Do not run this build on mainnet.");
    process.exit(1);
  }
  if (!/InvalidMessage|num_signers/i.test(errText)) {
    log("\n❌ FAIL — rejected, but not by the expected guard:");
    log("  ", errText.split("\n")[0]);
    process.exit(1);
  }
  log("    ✅ rejected on-chain by the num_signers guard");

  // ── Control: an ordinary single-signer proposal must still work ──
  log("\n[3] Control — ordinary num_signers=1 proposal from the same multisig");
  await connection.confirmTransaction(
    await connection.sendTransaction(
      new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: deployer.publicKey,
          toPubkey: vaultPda,
          lamports: 0.01 * LAMPORTS_PER_SOL,
        })
      ),
      [deployer]
    ),
    "confirmed"
  );

  const recipient = Keypair.generate();
  const created = await client.createTransaction(
    multisigAddress,
    0,
    [
      SystemProgram.transfer({
        fromPubkey: vaultPda,
        toPubkey: recipient.publicKey,
        lamports: 0.005 * LAMPORTS_PER_SOL,
      }),
    ],
    members[0],
    deployer
  );
  for (let i = 0; i < threshold; i++) {
    await client.approveTransaction(
      multisigAddress,
      created.transactionIndex,
      members[i]
    );
  }
  // remaining_accounts must mirror the proposal's static account_keys order.
  await client.executeTransaction(
    multisigAddress,
    created.transactionIndex,
    deployer,
    [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ]
  );
  const got = await connection.getBalance(recipient.publicKey);
  if (got !== 0.005 * LAMPORTS_PER_SOL) {
    log(`\n❌ FAIL — legitimate flow broken (recipient got ${got} lamports)`);
    process.exit(1);
  }
  log("    ✅ legitimate single-signer transfer executed normally");

  log("\n=== SECURITY TEST PASSED ===");
  log("Deployed program blocks the paymaster signer-borrow attack");
  log("and still executes ordinary vault-signed proposals.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
