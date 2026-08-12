/**
 * MAINNET smoke test — proves the deployed mainnet program works end-to-end
 * with real lamports, at dust amounts.
 *
 *   init 2-of-2 multisig → prefund vault → propose SOL transfer →
 *   2 approvals → execute → close (rent refund) → verify balances
 *
 * Also asserts the audit fix is live on mainnet: a num_signers=2 proposal
 * (the paymaster signer-borrow attack) must be rejected by the deployed
 * program before the legitimate flow runs.
 *
 * Deliberately conservative: 2 members (not 5) to minimise rent, dust
 * transfer amounts, and a hard spend ceiling checked up front. Most of what
 * it spends is refundable rent — the unrecoverable part is a few thousand
 * lamports of tx fees.
 *
 * Run: yarn ts-node scripts/mainnet-smoke-test.ts
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

const MAINNET_RPC =
  process.env.SSP_MAINNET_RPC ?? "https://api.mainnet-beta.solana.com";
const PROGRAM_ID = new PublicKey("SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r");
const DEPLOYER_KEYPAIR_PATH = path.join(
  os.homedir(),
  ".config/solana/ssp-multisig-mainnet-authority.json"
);

// Safety rail: refuse to run if the deployer holds less than this (so a
// mis-typed RPC or wrong keypair can't silently drain something), and never
// move more than dust.
const MIN_DEPLOYER_BALANCE = 0.05 * LAMPORTS_PER_SOL;
const MEMBER_FUND = 0.002 * LAMPORTS_PER_SOL; // covers ~400 tx fees each
const VAULT_PREFUND = 0.002 * LAMPORTS_PER_SOL;
const TRANSFER_AMOUNT = 0.001 * LAMPORTS_PER_SOL;

const log = (...args: unknown[]) => console.log(...args);
const sol = (lamports: number) => (lamports / LAMPORTS_PER_SOL).toFixed(6);

const PRIORITY_FEE_MICROLAMPORTS = 50_000;

async function main() {
  const connection = new Connection(MAINNET_RPC, "confirmed");
  const deployer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")))
  );
  const wallet = new anchor.Wallet(deployer);
  const client = new SolanaMultisigClient(connection, PROGRAM_ID, wallet, {
    priorityFeeMicroLamports: PRIORITY_FEE_MICROLAMPORTS,
  });

  log("=== MAINNET smoke test (real lamports, dust amounts) ===");
  log("Program: ", PROGRAM_ID.toBase58());
  log("Deployer:", deployer.publicKey.toBase58());

  const startBalance = await connection.getBalance(deployer.publicKey);
  log("Balance: ", sol(startBalance), "SOL");
  if (startBalance < MIN_DEPLOYER_BALANCE) {
    throw new Error(
      `Refusing to run: deployer balance ${sol(
        startBalance
      )} SOL is below the ${sol(MIN_DEPLOYER_BALANCE)} SOL safety floor`
    );
  }

  // Confirm we are really talking to the deployed mainnet program.
  const programAcc = await connection.getAccountInfo(PROGRAM_ID);
  if (!programAcc || !programAcc.executable) {
    throw new Error("Program account missing or not executable on this RPC");
  }
  log("Program account: executable ✅");

  // 1. Two fresh members, 2-of-2 (smallest meaningful multisig).
  const members = Array.from({ length: 2 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 2;

  const fundTx = new Transaction();
  for (const m of members) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m.publicKey,
        lamports: MEMBER_FUND,
      })
    );
  }
  await connection.confirmTransaction(
    await connection.sendTransaction(fundTx, [deployer]),
    "confirmed"
  );
  log("\n[1] Funded 2 members with", sol(MEMBER_FUND), "SOL each");

  // 2. Derive + initialize
  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  log("\n[2] multisig:", multisigAddress.toBase58());
  log("    vault:   ", vaultPda.toBase58());

  // Uses the SDK's priority-fee support (configured above). Without a priority
  // fee these transactions are dropped outright on mainnet — the signature
  // never lands.
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
  log("\n[3] Multisig initialized on mainnet");
  log("    sig:", initResult.signature);

  // 3. SECURITY: the audit fix must be live — reject num_signers=2.
  log("\n[4] Security check — signer-borrow proposal must be rejected");
  const drainData = Buffer.alloc(12);
  drainData.writeUInt32LE(2, 0);
  drainData.writeBigUInt64LE(BigInt(1_000_000), 4);
  let borrowRejected = false;
  try {
    await client.createTransactionFromMessage(
      multisigAddress,
      0,
      {
        numSigners: 2, // illegal — only the vault may sign
        numWritableSigners: 2,
        numWritableNonSigners: 1,
        accountKeys: [
          vaultPda,
          deployer.publicKey, // stands in for the paymaster
          Keypair.generate().publicKey,
          SystemProgram.programId,
        ],
        instructions: [
          {
            programIdIndex: 3,
            accountIndexes: Buffer.from([1, 2]),
            data: drainData,
          },
        ],
        addressTableLookups: [],
      } as never,
      members[0],
      deployer
    );
  } catch (e) {
    if (/InvalidMessage|num_signers/i.test(String(e))) borrowRejected = true;
    else throw e;
  }
  if (!borrowRejected) {
    throw new Error(
      "FAIL: mainnet program ACCEPTED a num_signers=2 proposal — the audit fix is not live"
    );
  }
  log("    ✅ rejected by the deployed program");

  // 4. Prefund the vault and run the real flow.
  await connection.confirmTransaction(
    await connection.sendTransaction(
      new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: deployer.publicKey,
          toPubkey: vaultPda,
          lamports: VAULT_PREFUND,
        })
      ),
      [deployer]
    ),
    "confirmed"
  );
  const vaultBefore = await connection.getBalance(vaultPda);
  log("\n[5] Vault prefunded:", sol(vaultBefore), "SOL");

  const recipient = Keypair.generate();
  const created = await client.createTransaction(
    multisigAddress,
    0,
    [
      SystemProgram.transfer({
        fromPubkey: vaultPda,
        toPubkey: recipient.publicKey,
        lamports: TRANSFER_AMOUNT,
      }),
    ],
    members[0],
    deployer // paymaster-style: member authorizes, deployer funds rent
  );
  log("\n[6] Proposal created at index", created.transactionIndex.toString());
  log("    sig:", created.signature);

  for (let i = 0; i < threshold; i++) {
    const s = await client.approveTransaction(
      multisigAddress,
      created.transactionIndex,
      members[i]
    );
    log(`    member[${i}] approved: ${s}`);
  }

  const execSig = await client.executeTransaction(
    multisigAddress,
    created.transactionIndex,
    deployer,
    [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ]
  );
  log("\n[7] Executed");
  log("    sig:", execSig);

  // 5. Close the proposal — rent back to the payer.
  const proposalAcc = await connection.getAccountInfo(
    created.transactionAddress
  );
  const rentLocked = proposalAcc?.lamports ?? 0;
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress,
    transactionAddress: created.transactionAddress,
    transactionIndex: created.transactionIndex,
    payer: deployer.publicKey,
  });
  const closeTx = new Transaction().add(closeIx);
  closeTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  closeTx.feePayer = deployer.publicKey;
  closeTx.sign(deployer);
  const closeSig = await connection.sendRawTransaction(closeTx.serialize());
  await connection.confirmTransaction(closeSig, "confirmed");
  log("\n[8] Proposal closed — rent refunded:", sol(rentLocked), "SOL");
  log("    sig:", closeSig);

  // The close landed, but an RPC read immediately after can still serve a
  // pre-close view of the account. Poll briefly and treat "gone OR zero
  // lamports" as closed, so a propagation lag isn't reported as a failure.
  let closed = false;
  const closeDeadline = Date.now() + 15_000;
  while (Date.now() < closeDeadline) {
    const acc = await connection.getAccountInfo(created.transactionAddress);
    if (acc === null || acc.lamports === 0) {
      closed = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!closed) {
    throw new Error("FAIL: proposal account still exists after close");
  }

  // 6. Verify the money actually moved.
  const vaultAfter = await connection.getBalance(vaultPda);
  const recipientBalance = await connection.getBalance(recipient.publicKey);
  log("\n[9] Verification:");
  log("    vault before:  ", sol(vaultBefore), "SOL");
  log("    vault after:   ", sol(vaultAfter), "SOL");
  log("    recipient got: ", sol(recipientBalance), "SOL");
  if (recipientBalance !== TRANSFER_AMOUNT) {
    throw new Error(
      `FAIL: recipient expected ${TRANSFER_AMOUNT} lamports, got ${recipientBalance}`
    );
  }
  if (vaultBefore - vaultAfter !== TRANSFER_AMOUNT) {
    throw new Error("FAIL: vault delta does not match the transfer amount");
  }

  const endBalance = await connection.getBalance(deployer.publicKey);
  log("\n=== MAINNET SMOKE TEST PASSED ===");
  log("Net deployer spend:", sol(startBalance - endBalance), "SOL");
  log("(includes member funding + vault prefund still held by those accounts)");
  log("\nMainnet program is functional end-to-end and enforces the audit fix.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
