#!/usr/bin/env ts-node

/**
 * Utility script to fund test accounts on Devnet
 * Usage: npm run fund-accounts
 */

import { Connection, Keypair, PublicKey, clusterApiUrl, LAMPORTS_PER_SOL } from '@solana/web3.js';

async function fundAccounts() {
    console.log("💰 Account Funding Utility for Devnet");
    console.log("=====================================\n");

    const connection = new Connection(clusterApiUrl('devnet'), 'confirmed');

    // Read addresses from command line arguments or generate test ones
    const addresses = process.argv.slice(2);
    
    if (addresses.length === 0) {
        console.log("Usage: ts-node fund-accounts.ts <address1> [address2] [address3]");
        console.log("Example: ts-node fund-accounts.ts 59Txsj9LZPkuFvzP29KjQkWicHjvHFfQAEoDqg3Fm9Dc");
        console.log("\nOr manually fund using Solana CLI:");
        console.log("solana airdrop 1 <address> --url devnet");
        return;
    }

    console.log(`Found ${addresses.length} addresses to fund:\n`);

    for (let i = 0; i < addresses.length; i++) {
        const address = addresses[i];
        console.log(`📍 Address ${i + 1}: ${address}`);
        
        try {
            // Check current balance
            const currentBalance = await connection.getBalance(new PublicKey(address));
            console.log(`   Current balance: ${currentBalance / LAMPORTS_PER_SOL} SOL`);

            if (currentBalance < 0.1 * LAMPORTS_PER_SOL) {
                console.log(`   Requesting airdrop...`);
                const signature = await connection.requestAirdrop(new PublicKey(address), 1 * LAMPORTS_PER_SOL);
                await connection.confirmTransaction(signature, 'confirmed');
                
                const newBalance = await connection.getBalance(new PublicKey(address));
                console.log(`   ✅ Funded! New balance: ${newBalance / LAMPORTS_PER_SOL} SOL`);
            } else {
                console.log(`   ✅ Already has sufficient balance`);
            }

            // Add delay to avoid rate limiting
            if (i < addresses.length - 1) {
                console.log(`   ⏳ Waiting 2 seconds to avoid rate limiting...`);
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        } catch (error) {
            console.log(`   ❌ Failed: ${error instanceof Error ? error.message : String(error)}`);
        }
        
        console.log(); // Empty line
    }

    console.log("🎉 Funding complete! You can now run the example.");
}

fundAccounts().catch(console.error);
