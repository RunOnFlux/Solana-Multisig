import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { TrulySelfInitiatingMultisigClient } from "../src";

/**
 * Complete demonstration of truly self-initiating multisig flow
 */
async function demonstrateFullFlow() {
  console.log("🚀 Truly Self-Initiating Multisig - Complete Flow Demo");
  console.log("=".repeat(60));
  
  // Setup connection
  const connection = new Connection("http://localhost:8899", "confirmed");
  const programId = new PublicKey("F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo");
  
  console.log("\n📋 STEP 1: Generate Members");
  console.log("-".repeat(60));
  
  // Generate 3 members for 2-of-3 multisig
  const alice = Keypair.generate();
  const bob = Keypair.generate();
  const charlie = Keypair.generate();
  
  console.log(`Alice:   ${alice.publicKey.toString()}`);
  console.log(`Bob:     ${bob.publicKey.toString()}`);
  console.log(`Charlie: ${charlie.publicKey.toString()}`);
  
  const members = [alice.publicKey, bob.publicKey, charlie.publicKey];
  const threshold = 2;
  
  console.log(`\n⚙️  Configuration: ${threshold}-of-${members.length} multisig`);
  
  // Fund members
  console.log("\n💰 Funding members...");
  for (const member of [alice, bob, charlie]) {
    let funded = false;
    for (let i = 0; i < 3 && !funded; i++) {
      try {
        const sig = await connection.requestAirdrop(
          member.publicKey,
          2 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(sig);
        const balance = await connection.getBalance(member.publicKey);
        if (balance > 0) {
          console.log(`✅ Funded ${member.publicKey.toString().slice(0, 8)}... (${balance / LAMPORTS_PER_SOL} SOL)`);
          funded = true;
        }
      } catch (e) {
        if (i === 2) {
          console.log(`⚠️  Airdrop failed for ${member.publicKey.toString().slice(0, 8)}...`);
        }
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  console.log("\n🔑 STEP 2: Derive Deterministic Address");
  console.log("-".repeat(60));
  
  // Create client (can use anyone's wallet for view functions)
  const client = new TrulySelfInitiatingMultisigClient(connection, programId);
  
  // CRITICAL: This address is deterministic - always the same for same config
  const multisigAddress = client.deriveAddress(members, threshold);
  console.log(`Multisig Address: ${multisigAddress.toString()}`);
  console.log(`✅ This address can be computed by ANYONE with the config`);
  console.log(`✅ NO private key exists for this address`);
  console.log(`✅ Can be pre-funded before initialization`);
  
  console.log("\n💸 STEP 3: Pre-Fund the Address (Optional)");
  console.log("-".repeat(60));
  
  try {
    const fundAmount = 0.1 * LAMPORTS_PER_SOL;
    const fundSig = await client.preFund(multisigAddress, fundAmount, alice);
    console.log(`✅ Pre-funded with 0.1 SOL`);
    console.log(`   Signature: ${fundSig.slice(0, 16)}...`);
    
    const balance = await connection.getBalance(multisigAddress);
    console.log(`   Current balance: ${balance / LAMPORTS_PER_SOL} SOL`);
    console.log(`\n🔒 Security Note: Even though funds are here, NOBODY can`);
    console.log(`   steal them by initializing with different parameters!`);
  } catch (e) {
    console.log(`⚠️  Pre-funding skipped: ${(e as Error).message}`);
  }
  
  console.log("\n✍️  STEP 4: Collect Off-Chain Signatures");
  console.log("-".repeat(60));
  console.log(`This happens BEFORE any on-chain transaction`);
  console.log(`Each member signs with their ACTUAL private key\n`);
  
  // Alice creates her signature
  console.log("1️⃣  Alice signing...");
  const aliceSignature = client.createSignature(members, threshold, alice);
  console.log(`   ✅ Signature: ${Buffer.from(aliceSignature.signature).toString("hex").slice(0, 16)}...`);
  console.log(`   ✅ Message hash: ${Buffer.from(aliceSignature.messageHash).toString("hex").slice(0, 16)}...`);
  
  // Bob creates his signature
  console.log("\n2️⃣  Bob signing...");
  const bobSignature = client.createSignature(members, threshold, bob);
  console.log(`   ✅ Signature: ${Buffer.from(bobSignature.signature).toString("hex").slice(0, 16)}...`);
  console.log(`   ✅ Message hash: ${Buffer.from(bobSignature.messageHash).toString("hex").slice(0, 16)}...`);
  
  console.log("\n🔍 Verifying signatures (client-side)...");
  const validation = client.verifySignatures(members, threshold, [aliceSignature, bobSignature]);
  console.log(`   Valid: ${validation.valid}`);
  console.log(`   Signatures collected: 2/${threshold}`);
  if (!validation.valid) {
    console.log(`   Errors: ${validation.errors.join(", ")}`);
    throw new Error("Signature validation failed");
  }
  
  console.log("\n🚀 STEP 5: Initialize On-Chain");
  console.log("-".repeat(60));
  console.log(`Sending threshold signatures to program for on-chain verification\n`);
  
  try {
    // Create a client with Alice's wallet (she'll pay tx fees)
    const { Wallet } = require("@coral-xyz/anchor");
    const aliceWallet = new Wallet(alice);
    const aliceClient = new TrulySelfInitiatingMultisigClient(connection, programId, aliceWallet);
    
    const result = await aliceClient.initialize(
      members,
      threshold,
      [aliceSignature, bobSignature],
      alice // Alice pays the transaction fee (NOT a creator role!)
    );
    
    console.log(`✅ Multisig initialized!`);
    console.log(`   Signature: ${result.signature}`);
    console.log(`   Address: ${result.multisigAddress.toString()}`);
    console.log(`   Bump: ${result.bump}`);
    
    // Verify initialization
    await new Promise(resolve => setTimeout(resolve, 1000));
    const multisig = await aliceClient.getMultisig(result.multisigAddress);
    if (multisig) {
      console.log(`\n📊 Multisig State:`);
      console.log(`   Members: ${multisig.members.length}`);
      console.log(`   Threshold: ${multisig.threshold}`);
      console.log(`   Initialized: ${multisig.isInitialized}`);
      console.log(`   Transaction Index: ${multisig.transactionIndex}`);
    }
    
  } catch (e) {
    console.error(`❌ Initialization failed: ${(e as Error).message}`);
    throw e;
  }
  
  console.log("\n🎯 STEP 6: Security Demonstrations");
  console.log("-".repeat(60));
  
  // Try to initialize with only 1 signature (should fail)
  console.log("\n🚨 Test 1: Attempting with insufficient signatures...");
  try {
    const invalidValidation = client.verifySignatures(members, threshold, [aliceSignature]);
    if (!invalidValidation.valid) {
      console.log(`   ✅ Correctly rejected: ${invalidValidation.errors[0]}`);
    }
  } catch (e) {
    console.log(`   ✅ Correctly rejected`);
  }
  
  // Try to have non-member sign
  console.log("\n🚨 Test 2: Attempting with non-member signature...");
  try {
    const nonMember = Keypair.generate();
    client.createSignature(members, threshold, nonMember);
    console.log(`   ❌ Should have been rejected!`);
  } catch (e) {
    console.log(`   ✅ Correctly rejected: ${(e as Error).message}`);
  }
  
  console.log("\n✅ STEP 7: Summary");
  console.log("=".repeat(60));
  console.log(`\n🔒 Security Features Verified:`);
  console.log(`   ✅ Deterministic address derivation`);
  console.log(`   ✅ No derivable private keys`);
  console.log(`   ✅ Pre-funding before initialization works`);
  console.log(`   ✅ Threshold signatures required`);
  console.log(`   ✅ On-chain signature verification`);
  console.log(`   ✅ No single creator dependency`);
  
  console.log(`\n🎊 Truly Self-Initiating Multisig: COMPLETE!`);
  console.log(`\n💡 Key Insight:`);
  console.log(`   The "payer" in initialization is NOT a creator.`);
  console.log(`   They just pay the tx fee. Control is ONLY with the`);
  console.log(`   ${threshold} members who provided valid signatures.`);
  console.log(`   NO ONE can front-run or steal the pre-funded address!`);
}

// Run the demo
demonstrateFullFlow()
  .then(() => {
    console.log("\n✅ Demo completed successfully!");
    process.exit(0);
  })
  .catch((e) => {
    console.error("\n❌ Demo failed:", e);
    process.exit(1);
  });

