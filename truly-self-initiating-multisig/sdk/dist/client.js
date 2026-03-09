"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrulySelfInitiatingMultisigClient = void 0;
const web3_js_1 = require("@solana/web3.js");
const anchor_1 = require("@coral-xyz/anchor");
const utils_1 = require("./utils");
/**
 * Main SDK client for Truly Self-Initiating Multisig
 */
class TrulySelfInitiatingMultisigClient {
    constructor(connection, programId, wallet) {
        this.connection = connection;
        this.programId = programId;
        // Create provider
        const provider = new anchor_1.AnchorProvider(connection, wallet || new anchor_1.Wallet(web3_js_1.Keypair.generate()), { commitment: "confirmed" });
        // Load program IDL
        this.program = new anchor_1.Program(require("../../../target/idl/truly_self_initiating_multisig.json"), provider);
    }
    /**
     * Derive the deterministic multisig address
     * This can be called by anyone and will always return the same address
     * for the same configuration
     */
    deriveAddress(members, threshold) {
        (0, utils_1.validateConfig)(members, threshold);
        const [address] = (0, utils_1.deriveMultisigAddress)(members, threshold, this.programId);
        return address;
    }
    /**
     * Create an initialization signature (off-chain)
     * Each member must call this with their private key
     */
    createSignature(members, threshold, memberKeypair) {
        (0, utils_1.validateConfig)(members, threshold);
        // Ensure the keypair is actually a member
        const sortedMembers = (0, utils_1.sortMembers)(members);
        if (!sortedMembers.some(m => m.equals(memberKeypair.publicKey))) {
            throw new Error("Keypair is not a member of this multisig");
        }
        return (0, utils_1.createInitSignature)(members, threshold, memberKeypair);
    }
    /**
     * Verify signatures (client-side validation before sending to chain)
     */
    verifySignatures(members, threshold, signatures) {
        const errors = [];
        try {
            (0, utils_1.validateConfig)(members, threshold);
        }
        catch (e) {
            errors.push(`Config validation failed: ${e.message}`);
            return { valid: false, errors };
        }
        // Check we have enough signatures
        if (signatures.length < threshold) {
            errors.push(`Insufficient signatures: need ${threshold}, got ${signatures.length}`);
        }
        // Verify each signature
        const sortedMembers = (0, utils_1.sortMembers)(members);
        const seenSigners = new Set();
        for (const sig of signatures) {
            // Check signer is a member
            if (!sortedMembers.some(m => m.equals(sig.signer))) {
                errors.push(`Signer ${sig.signer.toString()} is not a member`);
                continue;
            }
            // Check for duplicates
            const signerStr = sig.signer.toString();
            if (seenSigners.has(signerStr)) {
                errors.push(`Duplicate signature from ${signerStr}`);
                continue;
            }
            seenSigners.add(signerStr);
            // Verify signature
            if (!(0, utils_1.verifySignature)(sig, members, threshold)) {
                errors.push(`Invalid signature from ${signerStr}`);
            }
        }
        return {
            valid: errors.length === 0,
            errors,
        };
    }
    /**
     * Initialize the multisig with collected signatures
     * This sends the transaction to chain where signatures are verified on-chain
     */
    async initialize(members, threshold, signatures, payer) {
        (0, utils_1.validateConfig)(members, threshold);
        // Client-side validation
        const validation = this.verifySignatures(members, threshold, signatures);
        if (!validation.valid) {
            throw new Error(`Signature validation failed:\n${validation.errors.join("\n")}`);
        }
        // Derive multisig address
        const sortedMembers = (0, utils_1.sortMembers)(members);
        const [multisigAddress, bump] = (0, utils_1.deriveMultisigAddress)(sortedMembers, threshold, this.programId);
        // Convert signatures to the format expected by the program
        const signaturesForProgram = signatures.map(sig => ({
            signer: sig.signer,
            signature: Array.from(sig.signature),
            messageHash: Array.from(sig.messageHash),
        }));
        // Create instruction
        const tx = await this.program.methods
            .initializeMultisig(sortedMembers, threshold, signaturesForProgram)
            .accounts({
            multisig: multisigAddress,
            payer: payer.publicKey,
            systemProgram: web3_js_1.SystemProgram.programId,
        })
            .signers([payer])
            .rpc();
        return {
            signature: tx,
            multisigAddress,
            bump,
        };
    }
    /**
     * Pre-fund a multisig address before initialization
     * This demonstrates that funds can be sent to the deterministic address
     * before the multisig is initialized on-chain
     */
    async preFund(address, amount, funder) {
        const tx = new web3_js_1.Transaction().add(web3_js_1.SystemProgram.transfer({
            fromPubkey: funder.publicKey,
            toPubkey: address,
            lamports: amount,
        }));
        const signature = await (0, web3_js_1.sendAndConfirmTransaction)(this.connection, tx, [funder], { commitment: "confirmed" });
        return signature;
    }
    /**
     * Get multisig account data
     */
    async getMultisig(address) {
        try {
            const account = await this.program.account.multisig.fetch(address);
            return {
                members: account.members,
                threshold: account.threshold,
                transactionIndex: account.transactionIndex,
                isInitialized: account.isInitialized,
                bump: account.bump,
            };
        }
        catch (e) {
            return null;
        }
    }
    /**
     * Create a transaction proposal
     */
    async createTransaction(multisigAddress, instructions, creator) {
        // Get multisig data
        const multisig = await this.getMultisig(multisigAddress);
        if (!multisig) {
            throw new Error("Multisig not found");
        }
        // Derive transaction PDA
        const [transactionAddress] = web3_js_1.PublicKey.findProgramAddressSync([
            Buffer.from("transaction"),
            multisigAddress.toBytes(),
            Buffer.from(multisig.transactionIndex.toString()),
        ], this.programId);
        // Convert instructions to serializable format
        const serializableInstructions = instructions.map(ix => ({
            programId: ix.programId,
            accounts: ix.keys.map(k => ({
                pubkey: k.pubkey,
                isSigner: k.isSigner,
                isWritable: k.isWritable,
            })),
            data: Array.from(ix.data),
        }));
        // Create transaction
        const tx = await this.program.methods
            .createTransaction(serializableInstructions)
            .accounts({
            multisig: multisigAddress,
            transaction: transactionAddress,
            member: creator.publicKey,
            systemProgram: web3_js_1.SystemProgram.programId,
        })
            .signers([creator])
            .rpc();
        return {
            signature: tx,
            transactionAddress,
            transactionIndex: multisig.transactionIndex,
        };
    }
    /**
     * Approve a transaction proposal
     */
    async approveTransaction(multisigAddress, transactionIndex, member) {
        // Derive transaction PDA
        const [transactionAddress] = web3_js_1.PublicKey.findProgramAddressSync([
            Buffer.from("transaction"),
            multisigAddress.toBytes(),
            Buffer.from(transactionIndex.toString()),
        ], this.programId);
        const tx = await this.program.methods
            .approveTransaction(transactionIndex)
            .accounts({
            multisig: multisigAddress,
            transaction: transactionAddress,
            member: member.publicKey,
        })
            .signers([member])
            .rpc();
        return tx;
    }
    /**
     * Execute an approved transaction
     */
    async executeTransaction(multisigAddress, transactionIndex, executor) {
        // Derive transaction PDA
        const [transactionAddress] = web3_js_1.PublicKey.findProgramAddressSync([
            Buffer.from("transaction"),
            multisigAddress.toBytes(),
            Buffer.from(transactionIndex.toString()),
        ], this.programId);
        const tx = await this.program.methods
            .executeTransaction(transactionIndex)
            .accounts({
            multisig: multisigAddress,
            transaction: transactionAddress,
            executor: executor.publicKey,
        })
            .signers([executor])
            .rpc();
        return tx;
    }
    /**
     * Get transaction data
     */
    async getTransaction(address) {
        try {
            const account = await this.program.account.transaction.fetch(address);
            return {
                multisig: account.multisig,
                index: account.index,
                creator: account.creator,
                instructions: account.instructions,
                approvers: account.approvers,
                executed: account.executed,
            };
        }
        catch (e) {
            return null;
        }
    }
}
exports.TrulySelfInitiatingMultisigClient = TrulySelfInitiatingMultisigClient;
