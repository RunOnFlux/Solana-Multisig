import { Connection, PublicKey, Keypair } from '@solana/web3.js';
import { MemberApproval, InitializationConfig } from './types';
/**
 * Truly self-initiating multisig that requires collective approval
 * Eliminates the creator dependency through threshold-based initialization
 */
export declare class TrulySelfInitiatingMultisig {
    private connection;
    private programId;
    constructor(connection: Connection, programId?: PublicKey);
    /**
     * Generate deterministic configuration ID
     */
    private generateConfigId;
    /**
     * Create the message that members must sign to approve initialization
     */
    private createApprovalMessage;
    /**
     * Generate deterministic create key from configuration
     */
    deriveCreateKey(members: PublicKey[], threshold: number, salt?: Buffer): Keypair;
    /**
     * Derive the multisig address that will be created
     */
    deriveMultisigAddress(members: PublicKey[], threshold: number, salt?: Buffer): PublicKey;
    /**
     * Create an approval signature for multisig initialization
     * Each member must call this to approve the configuration
     */
    createApproval(config: InitializationConfig, memberKeypair: Keypair, timestamp?: number): Promise<MemberApproval>;
    /**
     * Verify a member approval signature
     */
    verifyApproval(config: InitializationConfig, approval: MemberApproval): boolean;
    /**
     * Validate that we have sufficient valid approvals for initialization
     */
    validateApprovals(config: InitializationConfig, approvals: MemberApproval[]): {
        isValid: boolean;
        approvedMembers: PublicKey[];
        errors: string[];
    };
    /**
     * Initialize multisig using collective approvals (truly self-initiating)
     * Any approved member can execute, but only with proof of collective approval
     */
    initializeMultisig(config: InitializationConfig, approvals: MemberApproval[], executor: Keypair): Promise<{
        signature: string;
        multisigAddress: PublicKey;
        createKey: PublicKey;
    }>;
    /**
     * Check if multisig is already initialized
     */
    isInitialized(multisigAddress: PublicKey): Promise<boolean>;
    /**
     * Pre-fund the multisig address before initialization
     */
    preFund(multisigAddress: PublicKey, funder: Keypair, amount?: number): Promise<string>;
    /**
     * Get current balance of an address
     */
    getBalance(address: PublicKey): Promise<number>;
    /**
     * Create initialization configuration object
     */
    createInitializationConfig(members: PublicKey[], threshold: number, options?: {
        salt?: Buffer;
        timeLock?: number;
        rentCollector?: PublicKey;
        memo?: string;
    }): InitializationConfig;
}
export default TrulySelfInitiatingMultisig;
//# sourceMappingURL=truly-self-initiating-multisig.d.ts.map