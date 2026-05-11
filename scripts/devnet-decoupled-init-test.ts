/**
 * Devnet smoke test — decoupled permissionless init.
 *
 * Mirrors the SSP Enterprise vault registration flow: the relay paymaster
 * pre-inits a multisig at its deterministic PDA WITHOUT any member being
 * present, signing, or even online. Members can then propose/approve/execute
 * sends at any later time on their own devices, on their own schedules.
 *
 * Demonstrates the core permissionless-init security property:
 *   - PDA = find_program_address([b"multisig", sha256(sorted_members), [t]])
 *   - Anyone can pay rent to register the canonical config there
 *   - No member signature is required for init — the canonical address
 *     can only be registered with the canonical member set (verified by the
 *     program's hash check)
 *   - Funds at the vault PDA are governed only by threshold-of-N approvals
 *     on `create_transaction` / `approve_transaction` / `execute_transaction`
 *
 * Also tests the "anyone can init" property by initing the multisig from a
 * paymaster who is not a member of the multisig.
 *
 * Run: yarn ts-node scripts/devnet-decoupled-init-test.ts
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

  log("=== Devnet decoupled-init smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Paymaster:", deployer.publicKey.toBase58());

  // 4-of-7 enterprise vault — well above the bundled single-tx ceiling, so
  // this test also confirms the M-of-N flow works split across separate txs.
  const memberCount = 7;
  const threshold = 4;
  const members = Array.from({ length: memberCount }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  log(`\n[1] Generated ${memberCount} member keypairs (target: ${threshold}-of-${memberCount})`);

  // Pre-derive the canonical PDA off-chain. Members don't need to be funded
  // or online for init.
  const sortedMembers = sortMembers(memberPubkeys);
  const [multisigPda] = deriveMultisigAddress(sortedMembers, threshold, PROGRAM_ID);
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);
  log("[2] Pre-derived multisig PDA:", multisigPda.toBase58());
  log("    Pre-derived vault PDA:   ", vaultPda.toBase58());

  // The paymaster is NOT a member — proves no member needs to be involved in init.
  const paymasterIsMember = sortedMembers.some((m) => m.equals(deployer.publicKey));
  log(`    Paymaster is a member? ${paymasterIsMember ? "YES (test invalid)" : "no — proves permissionless init"}`);
  if (paymasterIsMember) {
    throw new Error("test setup error: paymaster ended up as a member");
  }

  // Build ALT with the 7 member pubkeys + SystemProgram so the init tx fits.
  const alt = await client.createMembersAddressLookupTable(memberPubkeys, deployer);
  log("[3] ALT created:", alt.toBase58());

  // ============================================================
  // STAGE 1: paymaster pre-inits the vault. No members present.
  // ============================================================
  log("\n--- STAGE 1: permissionless init (paymaster only, no members) ---");
  const beforeMembersBalance = await Promise.all(
    memberPubkeys.slice(0, threshold).map((pk) => connection.getBalance(pk))
  );
  for (let i = 0; i < threshold; i++) {
    if (beforeMembersBalance[i] !== 0) {
      throw new Error(`member[${i}] has balance ${beforeMembersBalance[i]} before init — should be 0 to prove they weren't involved`);
    }
  }
  log("    ✅ confirmed: all members have 0 balance (never funded, never online)");

  const initResult = await client.initialize(
    memberPubkeys,
    threshold,
    deployer, // paymaster, not a member
    alt
  );
  log("    ✅ init tx:", initResult.signature);

  // Verify on-chain state matches the canonical inputs.
  const msState = await client.getMultisig(multisigPda);
  if (!msState) throw new Error("multisig not initialized");
  if (msState.threshold !== threshold) {
    throw new Error(`stored threshold ${msState.threshold} != expected ${threshold}`);
  }
  if (msState.members.length !== memberCount) {
    throw new Error(`stored member count ${msState.members.length} != expected ${memberCount}`);
  }
  const storedSorted = msState.members.map((p: PublicKey) => p.toBase58()).sort();
  const expectedSorted = sortedMembers.map((p) => p.toBase58()).sort();
  if (JSON.stringify(storedSorted) !== JSON.stringify(expectedSorted)) {
    throw new Error("stored members do not match canonical sorted_members");
  }
  log(`    ✅ on-chain state: ${threshold}-of-${memberCount}, canonical members`);

  // ============================================================
  // STAGE 2: pre-fund the vault. Anyone can do this anytime.
  // ============================================================
  const prefundTx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: deployer.publicKey,
      toPubkey: vaultPda,
      lamports: 0.01 * LAMPORTS_PER_SOL,
    })
  );
  const prefundSig = await connection.sendTransaction(prefundTx, [deployer]);
  await connection.confirmTransaction(prefundSig, "confirmed");
  log(`[4] Vault prefunded with 0.01 SOL: ${prefundSig}`);

  // ============================================================
  // STAGE 3: members come online later. Each member signs ONLY their own
  // approve — the paymaster pays all rent and tx fees so members never need
  // to hold SOL. This is the SSP Enterprise model.
  // ============================================================
  log("\n--- STAGE 3: members come online to send funds out (separate txs) ---");

  // Member[0] proposes — paymaster co-signs to fund rent.
  const recipient = Keypair.generate().publicKey;
  const transferLamports = BigInt(0.005 * LAMPORTS_PER_SOL);
  const proposalMessage = {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 1,
    accountKeys: [vaultPda, recipient, SystemProgram.programId],
    instructions: [
      {
        programIdIndex: 2, // SystemProgram
        accountIndexes: new Uint8Array([0, 1]), // [vault, recipient]
        data: new Uint8Array(
          SystemProgram.transfer({
            fromPubkey: vaultPda,
            toPubkey: recipient,
            lamports: transferLamports,
          }).data
        ),
      },
    ],
    addressTableLookups: [],
  };

  const currentIndex = BigInt(msState.transactionIndex.toString());
  const { instruction: createIx, transactionAddress, transactionIndex } =
    await client.buildCreateTransactionInstruction({
      multisigAddress: multisigPda,
      currentTransactionIndex: currentIndex,
      vaultIndex: 0,
      message: proposalMessage,
      creator: members[0].publicKey,
      payer: deployer.publicKey, // paymaster pays rent
    });

  const createTx = new Transaction().add(createIx);
  createTx.feePayer = deployer.publicKey;
  createTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  createTx.partialSign(deployer, members[0]);
  const createSig = await connection.sendRawTransaction(createTx.serialize());
  await connection.confirmTransaction(createSig, "confirmed");
  log(`    ✅ member[0] proposed (paymaster-funded tx): ${createSig}`);

  // Each of the 4 approvers signs in their OWN tx — no coordination needed,
  // they could be hours/days apart in production. Paymaster pays tx fees.
  for (let i = 0; i < threshold; i++) {
    const approveIx = await client.buildApproveTransactionInstruction({
      multisigAddress: multisigPda,
      transactionAddress,
      transactionIndex,
      member: members[i].publicKey,
    });
    const approveTx = new Transaction().add(approveIx);
    approveTx.feePayer = deployer.publicKey;
    approveTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    approveTx.partialSign(deployer, members[i]);
    const sig = await connection.sendRawTransaction(approveTx.serialize());
    await connection.confirmTransaction(sig, "confirmed");
    log(`    ✅ member[${i}] approved (paymaster-funded tx): ${sig}`);
  }

  // Execute + close in the same tx. Paymaster funds the executor signer slot;
  // anyone could execute here.
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    executor: deployer.publicKey,
    remainingAccounts: [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: recipient, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    payer: deployer.publicKey,
  });
  const execTx = new Transaction().add(executeIx, closeIx);
  const execSig = await connection.sendTransaction(execTx, [deployer]);
  await connection.confirmTransaction(execSig, "confirmed");
  log(`    ✅ executed + closed (paymaster tx): ${execSig}`);

  // ============================================================
  // Verify
  // ============================================================
  const recipientBalance = await connection.getBalance(recipient);
  log(`\n[6] Recipient balance: ${sol(recipientBalance)} SOL (expected 0.005)`);
  if (recipientBalance !== Number(transferLamports)) {
    throw new Error("recipient did not receive the transfer");
  }

  log("\n=== DECOUPLED INIT TEST PASSED ===");
  log("Demonstrates SSP Enterprise vault flow:");
  log("  - Paymaster (relay) inits multisig with no member involvement");
  log("  - Members come online later, each in their own tx");
  log("  - 4-of-7 threshold reached across 4 separate approve txs");
  log("  - Permissionless init + threshold gate on funds = secure");
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
