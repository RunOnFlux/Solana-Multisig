/**
 * Devnet SPL token smoke test — proves the deployed program can move SPL
 * tokens out of a vault.
 *
 *   create mint → init 3-of-5 multisig → mint tokens to vault ATA →
 *   propose token transfer → 3 approvals → execute → verify recipient ATA
 *
 * Run: yarn ts-node scripts/devnet-spl-smoke-test.ts
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
import {
  createAssociatedTokenAccountInstruction,
  createMint,
  createTransferInstruction,
  getAccount,
  getAssociatedTokenAddressSync,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
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

  log("=== Devnet SPL token smoke test ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer:", deployer.publicKey.toBase58());

  const startBalance = await connection.getBalance(deployer.publicKey);
  log("Deployer balance:", sol(startBalance), "SOL");

  // 1. Create a fresh SPL mint (deployer = mint authority, 6 decimals)
  log("\n[1] Creating SPL mint...");
  const mint = await createMint(
    connection,
    deployer,
    deployer.publicKey,
    null,
    6
  );
  log("    mint:", mint.toBase58());

  // 2. Generate 5 member keypairs for 3-of-5 multisig + fund them
  const members = Array.from({ length: 5 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 3;

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
  log("\n[2] Funded 5 members with", sol(memberFundLamports), "SOL each");

  // 3. Init multisig
  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);
  const sigs = members
    .slice(0, threshold)
    .map((m) => client.createSignature(memberPubkeys, threshold, m));
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  const initResult = await client.initialize(
    memberPubkeys,
    threshold,
    sigs,
    deployer,
    alt
  );
  log("\n[3] Multisig initialized:", multisigAddress.toBase58());
  log("    Vault PDA:           ", vaultPda.toBase58());
  log("    init sig:", initResult.signature);

  // 4. Create the vault's ATA + mint tokens to it
  // (vault is system-owned, but spl-token "owner" is the authority pubkey
  //  stored inside the token account — allowOwnerOffCurve=true permits PDAs)
  const vaultAta = getAssociatedTokenAddressSync(mint, vaultPda, true);
  const createAtaIx = createAssociatedTokenAccountInstruction(
    deployer.publicKey,
    vaultAta,
    vaultPda,
    mint
  );
  const ataTx = new Transaction().add(createAtaIx);
  const ataSig = await connection.sendTransaction(ataTx, [deployer]);
  await connection.confirmTransaction(ataSig, "confirmed");

  const startingTokenBalance = BigInt(1_000_000); // 1.0 token at 6 decimals
  await mintTo(
    connection,
    deployer,
    mint,
    vaultAta,
    deployer,
    startingTokenBalance
  );
  log("\n[4] Vault ATA:", vaultAta.toBase58());
  log("    Minted", startingTokenBalance.toString(), "base units to vault");

  // 5. Setup a recipient ATA
  const recipientOwner = Keypair.generate();
  const recipientAtaAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    deployer,
    mint,
    recipientOwner.publicKey
  );
  const recipientAta = recipientAtaAccount.address;
  log("\n[5] Recipient owner:", recipientOwner.publicKey.toBase58());
  log("    Recipient ATA:  ", recipientAta.toBase58());

  // 6. Build the SPL token transfer instruction (vault is the authority)
  const transferAmount = BigInt(250_000); // 0.25 tokens
  const transferIx = createTransferInstruction(
    vaultAta,
    recipientAta,
    vaultPda,
    transferAmount
  );

  // 7. Compile to V0 message format. account_keys layout:
  //    [0] vault (writable signer — vault PDA needs to sign as authority)
  //    [1] vault ATA (writable non-signer — source)
  //    [2] recipient ATA (writable non-signer — dest)
  //    [3] token program (readonly non-signer)
  const message = {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 2,
    accountKeys: [vaultPda, vaultAta, recipientAta, TOKEN_PROGRAM_ID],
    instructions: [
      {
        programIdIndex: 3,
        accountIndexes: new Uint8Array([1, 2, 0]), // [source, dest, authority]
        data: new Uint8Array(transferIx.data),
      },
    ],
    addressTableLookups: [],
  };

  // payer = deployer exercises the payer ≠ creator decoupling.
  const createResult = await client.createTransactionFromMessage(
    multisigAddress,
    0,
    message,
    members[0],
    deployer
  );
  log(
    "\n[6] Proposal created at index",
    createResult.transactionIndex.toString()
  );
  log("    sig:", createResult.signature);
  log("    creator: members[0] | payer:", deployer.publicKey.toBase58());

  // 8. Threshold approvals
  log("\n[7] Collecting approvals...");
  for (let i = 0; i < threshold; i++) {
    const approveSig = await client.approveTransaction(
      multisigAddress,
      createResult.transactionIndex,
      members[i]
    );
    log(`    member[${i}] approved:`, approveSig);
  }

  // 9. Execute (deployer is the executor)
  const remainingAccounts = [
    { pubkey: vaultPda, isSigner: false, isWritable: true },
    { pubkey: vaultAta, isSigner: false, isWritable: true },
    { pubkey: recipientAta, isSigner: false, isWritable: true },
    { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  const execSig = await client.executeTransaction(
    multisigAddress,
    createResult.transactionIndex,
    deployer,
    remainingAccounts
  );
  log("\n[8] Executed");
  log("    sig:", execSig);

  // 10. Verify
  const recipientBalance = (await getAccount(connection, recipientAta)).amount;
  const vaultBalance = (await getAccount(connection, vaultAta)).amount;
  log("\n[9] Verification:");
  log("    recipient received:", recipientBalance.toString(), "base units");
  log("    vault remaining:   ", vaultBalance.toString(), "base units");

  if (recipientBalance !== transferAmount) {
    throw new Error(
      `FAIL: expected recipient to have ${transferAmount}, got ${recipientBalance}`
    );
  }
  if (vaultBalance !== startingTokenBalance - transferAmount) {
    throw new Error(
      `FAIL: vault delta mismatch — start=${startingTokenBalance} after=${vaultBalance} expected=${
        startingTokenBalance - transferAmount
      }`
    );
  }

  const endBalance = await connection.getBalance(deployer.publicKey);
  log("\n=== SPL TOKEN SMOKE TEST PASSED ===");
  log("Total SOL spent:", sol(startBalance - endBalance));
  log("Devnet program is functional for SPL token transfers.");
  log("\nReproducible artifacts:");
  log("  Mint:           ", mint.toBase58());
  log("  Multisig:       ", multisigAddress.toBase58());
  log("  Vault PDA:      ", vaultPda.toBase58());
  log("  Vault ATA:      ", vaultAta.toBase58());
  log("  Recipient ATA:  ", recipientAta.toBase58());
  log("  Execute tx:     ", execSig);
}

main().catch((err) => {
  console.error("\n!!! SPL TOKEN SMOKE TEST FAILED:");
  console.error(err);
  process.exit(1);
});
