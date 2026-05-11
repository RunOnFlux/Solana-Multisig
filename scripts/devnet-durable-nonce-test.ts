/**
 * Devnet smoke test — durable nonce flow end-to-end.
 *
 * Proves that the wallet-pre-signs / Key-broadcasts-later pattern survives
 * arbitrary delays between wallet sign and key sign, with no blockhash race.
 *
 * Sequence:
 *   1. Init a 2-of-2 multisig (permissionless)
 *   2. Provision a durable nonce account at the canonical derived address
 *   3. Prefund the vault
 *   4. Build a bundled send tx using the nonce as recentBlockhash
 *   5. Wallet partial-signs (with its leaf, as creator + first approver)
 *   6. INTENTIONAL SLEEP for 90 seconds — way past the 60s blockhash window
 *   7. Key partial-signs the same tx bytes (nonce hasn't moved)
 *   8. Broadcast — succeeds because nonce is still valid
 *
 * If this works after a 90s pause, real wallet→push→user-approve flows
 * (which take 5-60 seconds usually) are bulletproof.
 *
 * Run: yarn ts-node scripts/devnet-durable-nonce-test.ts
 */
import * as anchor from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  NonceAccount,
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

  log("=== Devnet durable-nonce smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer (paymaster):", deployer.publicKey.toBase58());

  const walletMember = Keypair.generate();
  const keyMember = Keypair.generate();
  log("\n[1] Members generated");
  log("    wallet leaf:", walletMember.publicKey.toBase58());
  log("    key leaf:   ", keyMember.publicKey.toBase58());

  // Fund the leaves (they sign as approver members).
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
  log("[3] Multisig PDA:", multisigPda.toBase58());
  log("    Vault PDA:   ", vaultPda.toBase58());

  // Init the multisig if not already.
  const existing = await client.getMultisig(multisigPda);
  if (!existing) {
    const alt = await client.createMembersAddressLookupTable(
      sortedMembers,
      deployer
    );
    await client.initialize(sortedMembers, 2, deployer, alt);
    log("[4] Multisig initialized");
  } else {
    log("[4] Multisig already initialized — reusing");
  }

  // Provision the durable nonce account.
  const nonceAccount = await deriveNonceAccount(multisigPda);
  log("[5] Nonce account (derived):", nonceAccount.toBase58());

  const nonceInfo = await connection.getAccountInfo(nonceAccount);
  if (!nonceInfo) {
    const result = await client.provisionNonce({
      multisigAddress: multisigPda,
      payer: deployer,
    });
    log("    ✅ provisioned:", result.signature);
  } else {
    log("    ✅ already provisioned — reusing");
  }

  // Prefund the vault.
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
  log("[6] Vault prefunded with 0.01 SOL");

  const recipient = Keypair.generate().publicKey;
  log("[7] Recipient:", recipient.toBase58());

  // ============================================================
  // BUILD the bundled send tx using the DURABLE NONCE
  // ============================================================
  log("\n--- Build bundled send tx ---");

  // 1. Fetch the current nonce VALUE from on-chain (the durable "blockhash").
  const nonceState = await connection.getNonceAndContext(nonceAccount);
  if (!nonceState.value) throw new Error("nonce account not initialized");
  const nonceValue = nonceState.value.nonce;
  log("    Nonce value:", nonceValue);

  // 2. Build inner proposal message.
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

  const multisigState = await client.getMultisig(multisigPda);
  if (!multisigState) throw new Error("multisig disappeared");

  const { instruction: createIx, transactionAddress, transactionIndex } =
    await client.buildCreateTransactionInstruction({
      multisigAddress: multisigPda,
      currentTransactionIndex: BigInt(
        multisigState.transactionIndex.toString()
      ),
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

  // 3. ix[0] = nonceAdvance. THE critical addition that signals durable nonce.
  const nonceAdvanceIx = SystemProgram.nonceAdvance({
    noncePubkey: nonceAccount,
    authorizedPubkey: deployer.publicKey, // paymaster is the nonce authority
  });

  // 4. Build the tx using nonceValue as the "recent blockhash".
  const msg = new TransactionMessage({
    payerKey: deployer.publicKey,
    recentBlockhash: nonceValue,
    instructions: [
      nonceAdvanceIx, // ix[0] — MUST be first for durable nonce
      createIx,
      approveWallet,
      approveKey,
      executeIx,
      closeIx,
    ],
  }).compileToV0Message();

  const tx = new VersionedTransaction(msg);

  // 5. Wallet partial-signs NOW (this is the "wallet pre-signs" moment).
  tx.sign([walletMember]);
  log("    ✅ wallet pre-signed");

  // ============================================================
  // SLEEP 90 SECONDS — past the 60s blockhash window
  // ============================================================
  const SLEEP_SEC = 90;
  log(
    `\n--- Sleeping ${SLEEP_SEC}s to prove the nonce survives past the 60s blockhash window ---`
  );
  for (let i = SLEEP_SEC; i > 0; i -= 10) {
    log(`    ${i}s remaining...`);
    await new Promise((r) => setTimeout(r, 10_000));
  }

  // ============================================================
  // Key signs and the tx is broadcast — much later
  // ============================================================
  tx.sign([keyMember]);
  log("    ✅ key signed (after 90s pause)");

  // Paymaster signs as fee payer + nonce authority.
  tx.sign([deployer]);
  log("    ✅ paymaster signed (fee payer + nonce auth)");

  const serialized = tx.serialize();
  log(`    tx size: ${serialized.length} bytes (cap: 1232)`);

  const sig = await connection.sendRawTransaction(serialized, {
    skipPreflight: false,
  });
  await connection.confirmTransaction(sig, "confirmed");
  log("    ✅ broadcast:", sig);

  // Verify recipient got the funds.
  const recipientBalance = await connection.getBalance(recipient);
  log(
    `\n[8] Recipient balance: ${sol(recipientBalance)} SOL (expected ${sol(Number(transferLamports))})`
  );
  if (BigInt(recipientBalance) !== transferLamports) {
    throw new Error("recipient balance mismatch");
  }

  // Verify nonce has advanced.
  const newNonceState = await connection.getNonceAndContext(nonceAccount);
  if (!newNonceState.value) throw new Error("nonce account disappeared");
  if (newNonceState.value.nonce === nonceValue) {
    throw new Error("nonce did not advance after tx");
  }
  log(`[9] Nonce advanced to a new value (single-use confirmed)`);

  log("\n=== DURABLE NONCE TEST PASSED ===");
  log(
    "Wallet pre-signed → 90s pause → Key signed → broadcast — no blockhash race."
  );
  log("This is the foundation for the user-in-the-loop SSP send UX.");
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
