import { Connection, PublicKey, Keypair, TransactionInstruction } from "@solana/web3.js";
import { Wallet } from "@coral-xyz/anchor";
import { SignatureData, InitializeResult, CreateTransactionResult, MultisigConfig, TransactionData } from "./types";
/**
 * Main SDK client for Truly Self-Initiating Multisig
 */
export declare class TrulySelfInitiatingMultisigClient {
    private connection;
    private program;
    private programId;
    constructor(connection: Connection, programId: PublicKey, wallet?: Wallet);
    /**
     * Derive the deterministic multisig address
     * This can be called by anyone and will always return the same address
     * for the same configuration
     */
    deriveAddress(members: PublicKey[], threshold: number): PublicKey;
    /**
     * Create an initialization signature (off-chain)
     * Each member must call this with their private key
     */
    createSignature(members: PublicKey[], threshold: number, memberKeypair: Keypair): SignatureData;
    /**
     * Verify signatures (client-side validation before sending to chain)
     */
    verifySignatures(members: PublicKey[], threshold: number, signatures: SignatureData[]): {
        valid: boolean;
        errors: string[];
    };
    /**
     * Initialize the multisig with collected signatures
     * This sends the transaction to chain where signatures are verified on-chain
     */
    initialize(members: PublicKey[], threshold: number, signatures: SignatureData[], payer: Keypair): Promise<InitializeResult>;
    /**
     * Pre-fund a multisig address before initialization
     * This demonstrates that funds can be sent to the deterministic address
     * before the multisig is initialized on-chain
     */
    preFund(address: PublicKey, amount: number, funder: Keypair): Promise<string>;
    /**
     * Get multisig account data
     */
    getMultisig(address: PublicKey): Promise<MultisigConfig | null>;
    /**
     * Create a transaction proposal
     */
    createTransaction(multisigAddress: PublicKey, instructions: TransactionInstruction[], creator: Keypair): Promise<CreateTransactionResult>;
    /**
     * Approve a transaction proposal
     */
    approveTransaction(multisigAddress: PublicKey, transactionIndex: bigint, member: Keypair): Promise<string>;
    /**
     * Execute an approved transaction
     */
    executeTransaction(multisigAddress: PublicKey, transactionIndex: bigint, executor: Keypair): Promise<string>;
    /**
     * Get transaction data
     */
    getTransaction(address: PublicKey): Promise<TransactionData | null>;
}
