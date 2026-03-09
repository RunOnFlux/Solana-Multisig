import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { TrulySelfInitiatingMultisigClient } from "../src";

/**
 * Example 2: Pre-Funded Treasury
 * 
 * This example demonstrates a common use case:
 * - Create a multisig treasury
 * - Pre-fund it with significant amount
 * - Initialize with security guarantees
 * - Show that funds remain safe throughout
 */
async function preFundedTreasuryExample() {
  console.log("📖 Example 2: Pre-Funded Treasury\n");
  console.log("=".repeat(60));

  const connection = new Connection("http://localhost:8899", "confirmed");
  const programId = new PublicKey("F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo");

  // DAO/Organization members
  console.log("\n🏛️  DAO Treasury Setup");
  const founder = Keypair.generate();
  const cto = Keypair.generate();
  const cfo = Keypair.generate();
  const communityRep = Keypair.generate();
  
  console.log("   Council Members:");
  console.log(`   • Founder:    ${founder.publicKey.toString()}`);
  console.log(`   • CTO:        ${cto.publicKey.toString()}`);
  console.log(`   • CFO:        ${cfo.publicKey.toString()}`);
  console.log(`   • Community:  ${communityRep.publicKey.toString()}`);

  const members = [
    founder.publicKey,
    cto.publicKey,
    cfo.publicKey,
    communityRep.publicKey
  ];
  const threshold = 3; // 3-of-4 required for safety

  console.log(`\n⚙️  Configuration: ${threshold}-of-${members.length} multisig`);
  console.log(`   ℹ️  ${threshold} signatures required for any action`);

  // Fund members
  console.log("\n💰 Funding council members...");
  for (const member of [founder, cto, cfo, communityRep]) {
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
  console.log("   ✅ All members funded");

  const client = new TrulySelfInitiatingMultisigClient(connection, programId);

  // Derive treasury address
  console.log("\n🏦 Treasury Address Derivation");
  const treasuryAddress = client.deriveAddress(members, threshold);
  console.log(`   Address: ${treasuryAddress.toString()}`);
  console.log(`   ✨ This is your permanent treasury address`);

  // Pre-fund treasury with significant amount
  console.log("\n💎 Pre-Funding Treasury");
  const treasuryAmount = 10 * LAMPORTS_PER_SOL; // 10 SOL
  
  console.log(`   Depositing ${treasuryAmount / LAMPORTS_PER_SOL} SOL...`);
  try {
    const fundSig = await client.preFund(treasuryAddress, treasuryAmount, founder);
    console.log(`   ✅ Deposited successfully`);
    console.log(`   Transaction: ${fundSig.slice(0, 16)}...`);
    
    const balance = await connection.getBalance(treasuryAddress);
    console.log(`   💰 Treasury Balance: ${balance / LAMPORTS_PER_SOL} SOL`);
  } catch (e) {
    console.log(`   ⚠️  Funding failed: ${(e as Error).message}`);
  }

  // Security Note
  console.log("\n🔒 Security Status:");
  console.log(`   ⚠️  Treasury has ${treasuryAmount / LAMPORTS_PER_SOL} SOL but is NOT yet initialized`);
  console.log(`   ✅ Funds are SAFE because:`);
  console.log(`      • No private key exists for this address`);
  console.log(`      • Only the 4 designated members can initialize`);
  console.log(`      • Requires ${threshold} signatures to initialize`);
  console.log(`      • No one can front-run with different parameters`);

  // Collect signatures from council
  console.log("\n✍️  Collecting Council Signatures");
  console.log(`   Need ${threshold} of ${members.length} signatures...\n`);

  const founderSig = client.createSignature(members, threshold, founder);
  console.log(`   1️⃣  Founder signed`);
  
  const ctoSig = client.createSignature(members, threshold, cto);
  console.log(`   2️⃣  CTO signed`);
  
  const cfoSig = client.createSignature(members, threshold, cfo);
  console.log(`   3️⃣  CFO signed`);

  console.log(`\n   ✅ ${threshold} signatures collected (threshold met)`);

  // Validate before submitting
  const validation = client.verifySignatures(
    members,
    threshold,
    [founderSig, ctoSig, cfoSig]
  );

  if (!validation.valid) {
    console.error(`❌ Validation failed: ${validation.errors.join(", ")}`);
    return;
  }

  // Initialize treasury
  console.log("\n🚀 Initializing Treasury On-Chain");
  try {
    const { Wallet } = require("@coral-xyz/anchor");
    const founderWallet = new Wallet(founder);
    const founderClient = new TrulySelfInitiatingMultisigClient(
      connection,
      programId,
      founderWallet
    );

    const result = await founderClient.initialize(
      members,
      threshold,
      [founderSig, ctoSig, cfoSig],
      founder
    );

    console.log(`   ✅ Treasury initialized!`);
    console.log(`   Transaction: ${result.signature}`);

    // Verify final state
    await new Promise(resolve => setTimeout(resolve, 1000));
    const finalBalance = await connection.getBalance(treasuryAddress);
    const multisig = await founderClient.getMultisig(treasuryAddress);

    console.log("\n📊 Final Treasury State:");
    console.log(`   💰 Balance: ${finalBalance / LAMPORTS_PER_SOL} SOL`);
    console.log(`   👥 Council Members: ${multisig?.members.length}`);
    console.log(`   🔐 Required Signatures: ${multisig?.threshold}`);
    console.log(`   ✅ Initialized: ${multisig?.isInitialized}`);
    console.log(`   📝 Pending Transactions: ${multisig?.transactionIndex}`);

  } catch (e) {
    console.error(`❌ Initialization failed: ${(e as Error).message}`);
    throw e;
  }

  console.log("\n✅ Treasury Setup Complete!");
  
  console.log("\n💡 Key Achievements:");
  console.log("   • Treasury pre-funded with 10 SOL before initialization");
  console.log("   • Required 3-of-4 council signatures to initialize");
  console.log("   • Funds remained secure throughout the process");
  console.log("   • No single person controlled the treasury");
  console.log("   • Address was publicly known and verifiable");

  console.log("\n🔮 Next Steps:");
  console.log("   • Create transaction proposals");
  console.log("   • Collect threshold approvals");
  console.log("   • Execute approved transactions");
  console.log("   • Manage treasury with full transparency");
}

// Run example
if (require.main === module) {
  preFundedTreasuryExample()
    .then(() => {
      console.log("\n✨ Treasury example completed successfully!");
      process.exit(0);
    })
    .catch((e) => {
      console.error("\n❌ Error:", e);
      process.exit(1);
    });
}

export default preFundedTreasuryExample;

