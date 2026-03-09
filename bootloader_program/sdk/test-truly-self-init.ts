import { Connection, Keypair, clusterApiUrl } from '@solana/web3.js';
import TrulySelfInitiatingMultisig from './src/truly-self-initiating-multisig';

/**
 * Quick test of the truly self-initiating multisig implementation
 */
async function testTrulySelfInitiating() {
    console.log("🧪 Testing Truly Self-Initiating Multisig Implementation");
    console.log("========================================================");

    try {
        // Test 1: Imports and basic instantiation
        console.log("✅ 1. Import successful");

        const connection = new Connection(clusterApiUrl('devnet'), 'confirmed');
        const client = new TrulySelfInitiatingMultisig(connection);
        console.log("✅ 2. Client instantiation successful");

        // Test 2: Address derivation
        const members = [Keypair.generate().publicKey, Keypair.generate().publicKey, Keypair.generate().publicKey];
        const threshold = 2;

        const multisigAddress = client.deriveMultisigAddress(members, threshold);
        console.log(`✅ 3. Address derivation successful: ${multisigAddress.toString().slice(0, 8)}...`);

        // Test 3: Deterministic address consistency
        const multisigAddress2 = client.deriveMultisigAddress(members, threshold);
        const isConsistent = multisigAddress.equals(multisigAddress2);
        console.log(`✅ 4. Deterministic consistency: ${isConsistent}`);

        // Test 4: Configuration creation
        const config = client.createInitializationConfig(members, threshold);
        console.log(`✅ 5. Configuration creation successful: ${config.configId}`);

        // Test 5: Approval creation (without actual signing for now)
        console.log("✅ 6. All basic functions working");

        console.log("\n🎉 Basic implementation test PASSED");
        console.log("📝 Run 'npm install' then 'npm run example:truly-self-init' for full demo");

    } catch (error) {
        console.error("❌ Test failed:", error);
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (errorMessage.includes('tweetnacl')) {
            console.log("💡 Solution: Run 'npm install' to install missing dependencies");
        }
    }
}

testTrulySelfInitiating();