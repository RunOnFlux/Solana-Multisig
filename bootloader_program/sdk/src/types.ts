import { PublicKey } from '@solana/web3.js';

/**
 * Signature for member approval of multisig initialization
 */
export interface MemberApproval {
    member: PublicKey;
    signature: Uint8Array;
    timestamp: number;
}

/**
 * Configuration for multisig initialization that members sign
 */
export interface InitializationConfig {
    members: PublicKey[];
    threshold: number;
    salt: Buffer;
    timeLock?: number;
    rentCollector?: PublicKey;
    memo?: string;
    configId: string; // Deterministic ID for this configuration
}

/**
 * Result of validation process for member approvals
 */
export interface ApprovalValidationResult {
    isValid: boolean;
    approvedMembers: PublicKey[];
    errors: string[];
}

/**
 * Result of multisig initialization
 */
export interface InitializationResult {
    signature: string;
    multisigAddress: PublicKey;
    createKey: PublicKey;
}

// Constants
export const SQUADS_PROGRAM_ID = new PublicKey('SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf');