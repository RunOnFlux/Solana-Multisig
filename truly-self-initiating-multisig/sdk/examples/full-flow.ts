/**
 * Full lifecycle example for the Truly Self-Initiating Multisig.
 *
 * Demonstrates the entire flow:
 *   1. Derive multisig + vault PDAs (off-chain, free)
 *   2. Pre-fund the vault address (anyone can — vault is just a system PDA)
 *   3. Collect threshold signatures of the canonical init message off-chain
 *   4. Submit init tx (Ed25519 verify ixs + initialize_multisig — SDK bundles both)
 *   5. Propose a SOL transfer out of the vault
 *   6. Members approve to reach threshold
 *   7. Execute — vault signs the inner CPI via invoke_signed and SOL leaves
 *
 * Architecture note:
 *   - Multisig PDA holds CONFIG (members, threshold, tx counter), program-owned with data
 *   - Vault PDA(s) hold FUNDS (SOL, SPL tokens), system-owned with no data
 *   - Users send funds TO the vault address, never the multisig address
 *   - vault_index = 0 by convention (the contract supports 0–255)
 *
 * Run against a local validator:
 *   $ solana-test-validator --reset
 *   $ anchor deploy
 *   $ ts-node sdk/examples/full-flow.ts
 */

import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisigClient } from "../src";
import { deriveVaultAddress } from "../src/utils";

const PROGRAM_ID = new PublicKey("F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo");
const VAULT_INDEX = 0;
const RPC_URL = "http://localhost:8899";

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const client = new TrulySelfInitiatingMultisigClient(connection, PROGRAM_ID);

  // ========================================================================
  // 1. Members + addresses
  // ========================================================================
  // In a real SSP integration these come from the user's wallet+key seeds
  // (Ed25519 derivation at the m/44'/501' path). For the demo we generate.
  const member1 = Keypair.generate();
  const member2 = Keypair.generate();
  const member3 = Keypair.generate();
  const members = [member1.publicKey, member2.publicKey, member3.publicKey];
  const threshold = 2;

  // Derive deterministic addresses BEFORE any on-chain action.
  const multisig = client.deriveAddress(members, threshold);
  const [vault] = deriveVaultAddress(multisig, VAULT_INDEX, PROGRAM_ID);

  console.log("Members:", members.map(m => m.toBase58()));
  console.log("Multisig PDA:", multisig.toBase58());
  console.log("Vault PDA   :", vault.toBase58(), "← deposit address");

  // ========================================================================
  // 2. Pre-fund the vault (anyone can — vault is system-owned)
  // ========================================================================
  // Use a "funder" keypair. In a real SSP flow this is the user themselves
  // sending SOL/USDC from Phantom/CEX/etc. to the vault address.
  const funder = Keypair.generate();
  await airdrop(connection, funder.publicKey, 2 * LAMPORTS_PER_SOL);
  await transferSol(connection, funder, vault, 1 * LAMPORTS_PER_SOL);
  console.log("Vault balance after pre-fund:", await connection.getBalance(vault));

  // ========================================================================
  // 3. Submit the init tx (SDK builds + sends Ed25519 ixs + initialize_multisig)
  // ========================================================================
  // Each threshold member signs the canonical init message off-chain.
  const sigs = [
    client.createSignature(members, threshold, member1),
    client.createSignature(members, threshold, member2),
  ];

  // The "payer" is whoever submits + pays the init rent (~0.002 SOL).
  // For SSP this is the relay hot wallet. Here we use member1 for simplicity.
  await airdrop(connection, member1.publicKey, 1 * LAMPORTS_PER_SOL);
  const initResult = await client.initialize(members, threshold, sigs, member1);
  console.log("Multisig initialized. Tx:", initResult.signature);

  // ========================================================================
  // 4. Propose a SOL transfer out of the vault
  // ========================================================================
  const recipient = Keypair.generate();
  const amount = 0.1 * LAMPORTS_PER_SOL;

  // Build a SystemProgram::transfer { from: vault, to: recipient, amount }.
  // The SDK helper auto-detects vault as the writable signer at index 0.
  const transferIx = SystemProgram.transfer({
    fromPubkey: vault,
    toPubkey: recipient.publicKey,
    lamports: amount,
  });

  await airdrop(connection, member1.publicKey, 0.1 * LAMPORTS_PER_SOL); // for tx fees
  const proposal = await client.createTransaction(
    multisig,
    VAULT_INDEX,
    [transferIx],
    member1
  );
  console.log("Proposal created. Index:", proposal.transactionIndex.toString());

  // ========================================================================
  // 5. Threshold approvals
  // ========================================================================
  await airdrop(connection, member2.publicKey, 0.1 * LAMPORTS_PER_SOL);
  await client.approveTransaction(multisig, proposal.transactionIndex, member1);
  await client.approveTransaction(multisig, proposal.transactionIndex, member2);
  console.log(`Approvals: ${threshold}/${threshold} reached`);

  // ========================================================================
  // 6. Execute
  // ========================================================================
  // remainingAccounts must list every account the inner CPI touches, in the
  // exact order: static account_keys (vault, recipient, system_program), then
  // any ALT-loaded accounts. Our message has no ALTs so just the static three.
  const balBefore = await connection.getBalance(recipient.publicKey);

  await client.executeTransaction(
    multisig,
    proposal.transactionIndex,
    member1,
    [
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ]
  );

  const balAfter = await connection.getBalance(recipient.publicKey);
  console.log(`Recipient received: ${(balAfter - balBefore) / LAMPORTS_PER_SOL} SOL`);

  // The vault signed the inner SystemProgram::transfer via invoke_signed
  // (vault PDA seeds are cached on the proposal at create time, used here at
  // execute). The multisig PDA never moved any funds — it's just the
  // governance layer that verified threshold approvals.
}

// ============================================================================
// Helpers
// ============================================================================

async function airdrop(connection: Connection, pubkey: PublicKey, lamports: number) {
  const sig = await connection.requestAirdrop(pubkey, lamports);
  await connection.confirmTransaction(sig, "confirmed");
}

async function transferSol(
  connection: Connection,
  from: Keypair,
  to: PublicKey,
  lamports: number
) {
  const tx = new Transaction().add(
    SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: to, lamports })
  );
  await sendAndConfirmTransaction(connection, tx, [from], { commitment: "confirmed" });
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
