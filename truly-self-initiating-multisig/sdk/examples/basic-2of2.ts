import { Connection, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TrulySelfInitiatingMultisigClient } from "../src";

/**
 * Example 1: Basic 2-of-2 Multisig
 * 
 * This example demonstrates the simplest multisig configuration:
 * - 2 members (Alice and Bob)
 * - Both signatures required (2-of-2)
 * - Complete initialization flow
 */
async function basic2of2Example() {
  console.log("📖 Example 1: Basic 2-of-2 Multisig\n");
  console.log("=" .repeat(60));

  // Connect to cluster
  const connection = new Connection("http://localhost:8899", "confirmed");
  const programId = new Keypair().publicKey; // Replace with actual program ID

  // Create two members
  const alice = Keypair.generate();
  const bob = Keypair.generate();
  
  console.log("\n👥 Members:");
  console.log(`   Alice: ${alice.publicKey.toString()}`);
  console.log(`   Bob:   ${bob.publicKey.toString()}`);

  // Configuration: Both must sign (2-of-2)
  const members = [alice.publicKey, bob.publicKey];
  const threshold = 2;
  
  console.log(`\n⚙️  Configuration: ${threshold}-of-${members.length} (both must sign)`);

  // Fund members for transaction fees
  console.log("\n💰 Funding members...");
  for (const member of [alice, bob]) {
    try {
      const sig = await connection.requestAirdrop(
        member.publicKey,
        1 * LAMPORTS_PER_SOL
      );
      await connection.confirmTransaction(sig);
      console.log(`   ✅ ${member.publicKey.toString().slice(0, 8)}... funded`);
    } catch (e) {
      console.log(`   ⚠️  Airdrop failed, continuing...`);
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  // Create client
  const client = new TrulySelfInitiatingMultisigClient(connection, programId);

  // Step 1: Derive deterministic address
  console.log("\n🔑 Step 1: Derive Multisig Address");
  const multisigAddress = client.deriveAddress(members, threshold);
  console.log(`   Address: ${multisigAddress.toString()}`);
  console.log(`   ℹ️  This address is deterministic - always the same for this config`);

  // Step 2: Pre-fund (optional but recommended)
  console.log("\n💸 Step 2: Pre-Fund Multisig");
  try {
    await client.preFund(multisigAddress, 0.5 * LAMPORTS_PER_SOL, alice);
    const balance = await connection.getBalance(multisigAddress);
    console.log(`   ✅ Pre-funded with ${balance / LAMPORTS_PER_SOL} SOL`);
  } catch (e) {
    console.log(`   ⚠️  Pre-funding skipped: ${(e as Error).message}`);
  }

  // Step 3: Collect signatures off-chain
  console.log("\n✍️  Step 3: Collect Signatures");
  console.log("   Each member signs with their private key...");
  
  const aliceSignature = client.createSignature(members, threshold, alice);
  console.log(`   ✅ Alice signed`);
  
  const bobSignature = client.createSignature(members, threshold, bob);
  console.log(`   ✅ Bob signed`);

  // Verify signatures client-side
  const validation = client.verifySignatures(
    members,
    threshold,
    [aliceSignature, bobSignature]
  );
  console.log(`   ✅ Validation: ${validation.valid ? "PASSED" : "FAILED"}`);

  if (!validation.valid) {
    console.error(`   ❌ Errors: ${validation.errors.join(", ")}`);
    return;
  }

  // Step 4: Initialize on-chain
  console.log("\n🚀 Step 4: Initialize On-Chain");
  try {
    // Use Wallet wrapper for Alice
    const { Wallet } = require("@coral-xyz/anchor");
    const aliceWallet = new Wallet(alice);
    const aliceClient = new TrulySelfInitiatingMultisigClient(
      connection,
      programId,
      aliceWallet
    );

    const result = await aliceClient.initialize(
      members,
      threshold,
      [aliceSignature, bobSignature],
      alice
    );

    console.log(`   ✅ Multisig initialized!`);
    console.log(`   Transaction: ${result.signature}`);
    console.log(`   Address: ${result.multisigAddress.toString()}`);

    // Verify on-chain state
    await new Promise(resolve => setTimeout(resolve, 1000));
    const multisig = await aliceClient.getMultisig(result.multisigAddress);
    
    if (multisig) {
      console.log(`\n📊 On-Chain State:`);
      console.log(`   Members: ${multisig.members.length}`);
      console.log(`   Threshold: ${multisig.threshold}`);
      console.log(`   Initialized: ${multisig.isInitialized}`);
      console.log(`   Transaction Count: ${multisig.transactionIndex}`);
    }

  } catch (e) {
    console.error(`   ❌ Initialization failed: ${(e as Error).message}`);
    throw e;
  }

  console.log("\n✅ Example Complete!");
  console.log("\n💡 Key Takeaways:");
  console.log("   • Both Alice and Bob had to sign to initialize");
  console.log("   • The address was known before initialization");
  console.log("   • Funds were safe in the pre-funded address");
  console.log("   • No single creator controlled the multisig");
}

// Run example
if (require.main === module) {
  basic2of2Example()
    .then(() => {
      console.log("\n✨ Success!");
      process.exit(0);
    })
    .catch((e) => {
      console.error("\n❌ Error:", e);
      process.exit(1);
    });
}

export default basic2of2Example;

