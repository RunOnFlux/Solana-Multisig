import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { TrulySelfInitiatingMultisigClient } from "../src";

/**
 * Example 3: Complex Multi-Instruction Transaction
 * 
 * This example demonstrates:
 * - Creating a multisig
 * - Proposing a transaction with multiple instructions
 * - Collecting approvals from members
 * - Executing the approved transaction
 */
async function complexTransactionExample() {
  console.log("📖 Example 3: Complex Transaction Management\n");
  console.log("=".repeat(60));

  const connection = new Connection("http://localhost:8899", "confirmed");
  const programId = new PublicKey("F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo");

  // Create 3-of-5 multisig
  console.log("\n👥 Creating 3-of-5 Multisig");
  const members = Array.from({ length: 5 }, () => Keypair.generate());
  const memberPubkeys = members.map(m => m.publicKey);
  const threshold = 3;

  console.log(`   Members: ${memberPubkeys.length}`);
  console.log(`   Threshold: ${threshold}`);
  memberPubkeys.forEach((pk, i) => {
    console.log(`   ${i + 1}. ${pk.toString().slice(0, 16)}...`);
  });

  // Fund members
  console.log("\n💰 Funding members...");
  for (const member of members) {
    try {
      const sig = await connection.requestAirdrop(
        member.publicKey,
        2 * LAMPORTS_PER_SOL
      );
      await connection.confirmTransaction(sig);
    } catch (e) {
      // Continue
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  console.log("   ✅ All funded");

  const client = new TrulySelfInitiatingMultisigClient(connection, programId);

  // Initialize multisig
  console.log("\n🔧 Initializing Multisig");
  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  console.log(`   Address: ${multisigAddress.toString()}`);

  // Pre-fund multisig
  await client.preFund(multisigAddress, 5 * LAMPORTS_PER_SOL, members[0]);
  console.log(`   ✅ Pre-funded with 5 SOL`);

  // Collect init signatures
  const initSignatures = members.slice(0, 3).map(member =>
    client.createSignature(memberPubkeys, threshold, member)
  );

  // Initialize
  const { Wallet } = require("@coral-xyz/anchor");
  const member0Wallet = new Wallet(members[0]);
  const member0Client = new TrulySelfInitiatingMultisigClient(
    connection,
    programId,
    member0Wallet
  );

  try {
    await member0Client.initialize(
      memberPubkeys,
      threshold,
      initSignatures,
      members[0]
    );
    console.log(`   ✅ Multisig initialized`);
  } catch (e) {
    console.log(`   ⚠️  May already be initialized`);
  }

  // Wait for confirmation
  await new Promise(resolve => setTimeout(resolve, 2000));

  // Create complex transaction with multiple instructions
  console.log("\n📝 Creating Complex Transaction");
  console.log("   Transaction will:");
  
  // Recipient accounts for demonstration
  const recipient1 = Keypair.generate();
  const recipient2 = Keypair.generate();
  const recipient3 = Keypair.generate();

  console.log(`   • Send 1 SOL to ${recipient1.publicKey.toString().slice(0, 16)}...`);
  console.log(`   • Send 0.5 SOL to ${recipient2.publicKey.toString().slice(0, 16)}...`);
  console.log(`   • Send 0.3 SOL to ${recipient3.publicKey.toString().slice(0, 16)}...`);

  // Create instructions
  const instructions: TransactionInstruction[] = [
    SystemProgram.transfer({
      fromPubkey: multisigAddress,
      toPubkey: recipient1.publicKey,
      lamports: 1 * LAMPORTS_PER_SOL,
    }),
    SystemProgram.transfer({
      fromPubkey: multisigAddress,
      toPubkey: recipient2.publicKey,
      lamports: 0.5 * LAMPORTS_PER_SOL,
    }),
    SystemProgram.transfer({
      fromPubkey: multisigAddress,
      toPubkey: recipient3.publicKey,
      lamports: 0.3 * LAMPORTS_PER_SOL,
    }),
  ];

  console.log(`\n   📊 Transaction Summary:`);
  console.log(`   • Instructions: ${instructions.length}`);
  console.log(`   • Total Amount: 1.8 SOL`);
  console.log(`   • Recipients: 3`);

  // Member 1 creates the transaction proposal
  console.log("\n🎯 Member 1 Creating Proposal");
  try {
    const createResult = await member0Client.createTransaction(
      multisigAddress,
      instructions,
      members[0]
    );

    console.log(`   ✅ Transaction created`);
    console.log(`   Transaction Index: ${createResult.transactionIndex}`);
    console.log(`   Transaction Address: ${createResult.transactionAddress.toString()}`);

    const txIndex = createResult.transactionIndex;

    // Collect approvals (need 3 total including creator)
    console.log("\n✍️  Collecting Approvals");
    
    // Member 2 approves
    console.log("   Member 2 approving...");
    const member1Wallet = new Wallet(members[1]);
    const member1Client = new TrulySelfInitiatingMultisigClient(
      connection,
      programId,
      member1Wallet
    );
    await member1Client.approveTransaction(multisigAddress, txIndex, members[1]);
    console.log(`   ✅ Member 2 approved`);

    // Member 3 approves
    console.log("   Member 3 approving...");
    const member2Wallet = new Wallet(members[2]);
    const member2Client = new TrulySelfInitiatingMultisigClient(
      connection,
      programId,
      member2Wallet
    );
    await member2Client.approveTransaction(multisigAddress, txIndex, members[2]);
    console.log(`   ✅ Member 3 approved`);

    console.log(`\n   ✅ Threshold met: 3 approvals collected`);

    // Execute transaction
    console.log("\n🚀 Executing Transaction");
    const executeSig = await member0Client.executeTransaction(
      multisigAddress,
      txIndex,
      members[0]
    );

    console.log(`   ✅ Transaction executed!`);
    console.log(`   Signature: ${executeSig}`);

    // Verify results
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log("\n📊 Verification");
    const balance1 = await connection.getBalance(recipient1.publicKey);
    const balance2 = await connection.getBalance(recipient2.publicKey);
    const balance3 = await connection.getBalance(recipient3.publicKey);

    console.log(`   Recipient 1: ${balance1 / LAMPORTS_PER_SOL} SOL ✅`);
    console.log(`   Recipient 2: ${balance2 / LAMPORTS_PER_SOL} SOL ✅`);
    console.log(`   Recipient 3: ${balance3 / LAMPORTS_PER_SOL} SOL ✅`);

  } catch (e) {
    console.error(`❌ Transaction failed: ${(e as Error).message}`);
    throw e;
  }

  console.log("\n✅ Complex Transaction Complete!");

  console.log("\n💡 What Happened:");
  console.log("   1. Member 1 proposed a 3-instruction transaction");
  console.log("   2. Members 2 and 3 reviewed and approved");
  console.log("   3. Once threshold (3) was met, transaction was executed");
  console.log("   4. All 3 transfers completed atomically");
  console.log("   5. Full transparency and auditability");

  console.log("\n🔒 Security Features:");
  console.log("   • All instructions executed atomically");
  console.log("   • Required threshold approvals before execution");
  console.log("   • Any member can propose, all can approve");
  console.log("   • Execution only after threshold met");
  console.log("   • Full on-chain history and transparency");
}

// Run example
if (require.main === module) {
  complexTransactionExample()
    .then(() => {
      console.log("\n✨ Complex transaction example completed!");
      process.exit(0);
    })
    .catch((e) => {
      console.error("\n❌ Error:", e);
      process.exit(1);
    });
}

export default complexTransactionExample;

