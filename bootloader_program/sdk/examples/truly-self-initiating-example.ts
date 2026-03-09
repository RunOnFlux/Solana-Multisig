import { Connection, Keypair, clusterApiUrl, LAMPORTS_PER_SOL } from '@solana/web3.js';
import TrulySelfInitiatingMultisig from '../src/truly-self-initiating-multisig';
import { MemberApproval } from '../src/types';

/**
 * Example demonstrating truly self-initiating multisig
 * NO SINGLE CREATOR - requires collective approval from threshold members
 */
async function demonstrateTrulySelfInitiatingMultisig() {
    console.log("🚀 Truly Self-Initiating Multisig - Collective Approval Demo");
    console.log("================================================================");
    console.log("🎯 This approach eliminates the creator dependency entirely!");
    console.log("✅ Multiple members must approve before ANY member can execute");
    console.log("✅ No single point of failure during initialization");
    console.log("✅ Executor is just transaction signer, not controller");
    console.log("\n💡 Note: If airdrops fail due to rate limiting, manually fund with:");
    console.log("   solana airdrop 1 <member-address> --url devnet\n");

    // Initialize connection (use devnet for testing)
    const connection = new Connection(clusterApiUrl('devnet'), 'confirmed');
    const client = new TrulySelfInitiatingMultisig(connection);

    // Create test members (in real scenario, these would be distributed)
    const member1 = Keypair.generate();
    const member2 = Keypair.generate();
    const member3 = Keypair.generate();
    const members = [member1.publicKey, member2.publicKey, member3.publicKey];
    const threshold = 2; // 2-of-3 multisig

    console.log("👥 Generated Members:");
    console.log(`Member 1: ${member1.publicKey.toString()}`);
    console.log(`Member 2: ${member2.publicKey.toString()}`);
    console.log(`Member 3: ${member3.publicKey.toString()}`);
    console.log(`⚙️  Configuration: ${threshold}-of-${members.length} multisig\n`);

    // Fund members for transaction fees
    console.log("💰 Funding members for transaction fees...");
    try {
        // Request airdrops (devnet only) - do them sequentially to avoid rate limits
        for (let i = 0; i < members.length; i++) {
            const member = members[i];
            try {
                // Check existing balance first
                const existingBalance = await connection.getBalance(member);
                if (existingBalance < 0.1 * LAMPORTS_PER_SOL) {
                    console.log(`   Requesting airdrop for Member ${i + 1}...`);
                    const airdropTx = await connection.requestAirdrop(member, 1 * LAMPORTS_PER_SOL);
                    await connection.confirmTransaction(airdropTx, 'confirmed');
                    console.log(`✅ Member ${i + 1} funded`);
                } else {
                    console.log(`✅ Member ${i + 1} already has sufficient balance`);
                }
                
                // Add delay between airdrops to avoid rate limiting
                if (i < members.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            } catch (airdropError) {
                console.log(`⚠️  Airdrop failed for Member ${i + 1}: ${airdropError instanceof Error ? airdropError.message : String(airdropError)}`);
            }
        }
    } catch (error) {
        console.log("⚠️  General airdrop error:", error instanceof Error ? error.message : String(error));
    }

    // Check final balances
    console.log("\n💰 Final member balances:");
    for (let i = 0; i < members.length; i++) {
        const balance = await connection.getBalance(members[i]);
        console.log(`   Member ${i + 1}: ${balance / LAMPORTS_PER_SOL} SOL`);
        if (balance === 0) {
            console.log("❌ Member has no balance! Example may fail. Please fund manually or use faucet.");
        }
    }

    // Derive deterministic addresses
    const multisigAddress = client.deriveMultisigAddress(members, threshold);
    console.log(`\n🔑 Derived Multisig Address: ${multisigAddress.toString()}`);

    // Pre-fund the multisig
    console.log("\n💰 Pre-funding multisig address...");
    try {
        // Find a member with sufficient balance to fund the multisig
        let funder: Keypair | null = null;
        for (let i = 0; i < members.length; i++) {
            const memberKeypair = [member1, member2, member3][i];
            const balance = await connection.getBalance(memberKeypair.publicKey);
            if (balance >= 0.02 * LAMPORTS_PER_SOL) { // Need at least 0.02 SOL (0.01 for prefund + fees)
                funder = memberKeypair;
                console.log(`   Using Member ${i + 1} as funder (balance: ${balance / LAMPORTS_PER_SOL} SOL)`);
                break;
            }
        }

        if (!funder) {
            console.log("❌ No member has sufficient balance for pre-funding. Skipping pre-funding step.");
            console.log("   💡 You can manually fund the members using: solana airdrop 1 <member-address> --url devnet");
        } else {
            await client.preFund(multisigAddress, funder, 0.01 * LAMPORTS_PER_SOL);
            const balance = await client.getBalance(multisigAddress);
            console.log(`✅ Pre-funded balance: ${balance / LAMPORTS_PER_SOL} SOL`);
        }
    } catch (error) {
        console.log(`⚠️  Pre-funding failed: ${error instanceof Error ? error.message : String(error)}`);
        console.log("   Continuing with example without pre-funding...");
    }

    // PHASE 1: COLLECTIVE APPROVAL GATHERING
    console.log("\n📋 PHASE 1: Collective Approval Gathering");
    console.log("==========================================");

    // Create initialization configuration
    const config = client.createInitializationConfig(members, threshold, {
        memo: "Truly Self-Initiating Demo"
    });
    console.log(`Configuration ID: ${config.configId}`);

    // Each member creates their approval signature (simulating off-chain coordination)
    console.log("\n✍️  Collecting member approvals...");
    
    // Member 1 approves
    console.log("1️⃣  Member 1 approving initialization...");
    const approval1 = await client.createApproval(config, member1);
    console.log(`   ✅ Member 1 approval signature: ${Buffer.from(approval1.signature).toString('hex').slice(0, 16)}...`);

    // Member 2 approves
    console.log("2️⃣  Member 2 approving initialization...");
    const approval2 = await client.createApproval(config, member2);
    console.log(`   ✅ Member 2 approval signature: ${Buffer.from(approval2.signature).toString('hex').slice(0, 16)}...`);

    // Collect approvals array
    const approvals = [approval1, approval2];

    // Validate we have enough approvals
    const validation = client.validateApprovals(config, approvals);
    console.log(`\n🔍 Approval Validation:`);
    console.log(`   Valid: ${validation.isValid}`);
    console.log(`   Approved members: ${validation.approvedMembers.length}/${threshold}`);
    console.log(`   Errors: ${validation.errors.length === 0 ? 'None' : validation.errors.join(', ')}`);

    if (!validation.isValid) {
        console.error("❌ Insufficient approvals! Cannot proceed.");
        return;
    }

    // PHASE 2: COLLECTIVE EXECUTION
    console.log("\n⚡ PHASE 2: Collective Execution");
    console.log("================================");
    console.log("🎯 ANY approved member can execute (redundancy)");
    console.log("🔒 But execution requires proof of collective approval");

    // Check if already initialized
    let isInitialized = await client.isInitialized(multisigAddress);
    console.log(`\nCurrent initialization status: ${isInitialized}`);

    if (!isInitialized) {
        console.log("\n🏗️  Executing collective initialization...");
        console.log("   📝 Using Member 1 as executor (could be any approved member)");

        // Execute initialization with collective approval
        const { signature: initSignature } = await client.initializeMultisig(
            config,
            approvals,
            member1 // Executor (could be member2 as well)
        );

        console.log(`✅ Multisig collectively initialized: ${initSignature}`);

        // Verify initialization
        isInitialized = await client.isInitialized(multisigAddress);
        console.log(`Initialization confirmed: ${isInitialized}`);
    }

    // PHASE 3: DEMONSTRATE SECURITY
    console.log("\n🔒 PHASE 3: Security Demonstration");
    console.log("===================================");

    // Try to initialize with insufficient approvals (should fail)
    console.log("\n🚨 Testing security: Attempting initialization with only 1 approval...");
    try {
        const insufficientApprovals = [approval1]; // Only 1 approval, need 2
        await client.initializeMultisig(config, insufficientApprovals, member1);
        console.log("❌ ERROR: Should have failed!");
    } catch (error) {
        console.log(`✅ Correctly rejected: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Try to execute as non-approved member (should fail)
    console.log("\n🚨 Testing security: Attempting execution by non-approved member...");
    try {
        // Member 3 didn't approve, so they can't execute
        await client.initializeMultisig(config, approvals, member3);
        console.log("❌ ERROR: Should have failed!");
    } catch (error) {
        console.log(`✅ Correctly rejected: ${error instanceof Error ? error.message : String(error)}`);
    }

    // PHASE 4: RESULTS SUMMARY
    console.log("\n🎉 PHASE 4: Results Summary");
    console.log("===========================");
    console.log(`✅ Multisig Address: ${multisigAddress.toString()}`);
    console.log(`✅ Initialization Status: ${isInitialized}`);
    console.log(`✅ Required Approvals: ${threshold}/${members.length}`);
    console.log(`✅ Actual Approvals: ${approvals.length}`);
    console.log(`✅ Security: No single creator dependency`);
    console.log(`✅ Truly Self-Initiating: ✓ ACHIEVED!`);

    console.log("\n🔄 Comparison with Previous Approaches:");
    console.log("   ❌ Traditional Squads: Single creator controls initialization");
    console.log("   ⚠️  Simple Approach: Single member can initialize (better but not ideal)");
    console.log("   ✅ Truly Self-Init: Requires collective approval from threshold members");

    console.log("\n🎯 Key Benefits of This Approach:");
    console.log("   🔒 No single point of failure during initialization");
    console.log("   👥 Collective decision-making from the start");
    console.log("   🔐 Cryptographic proof of member consent");
    console.log("   🔄 Any approved member can execute (redundancy)");
    console.log("   📏 Deterministic addresses for pre-funding");
    console.log("   🚀 Truly trustless and decentralized");

    console.log("\n🎊 Demo completed successfully!");
}

// Run the demonstration
demonstrateTrulySelfInitiatingMultisig().catch(console.error);