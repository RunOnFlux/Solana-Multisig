import { PublicKey, Keypair } from '@solana/web3.js';
import { createHash } from 'node:crypto';
import { SQUADS_PROGRAM_ID } from './types';

/**
 * Validates that a multisig configuration is valid
 */
export function validateMultisigConfig(members: PublicKey[], threshold: number): void {
    // Validate members count first
    if (members.length === 0) {
        throw new Error('At least one member is required');
    }

    if (members.length > 10) {
        throw new Error('Maximum 10 members allowed');
    }

    // Check for duplicate members
    const uniqueMembers = new Set(members.map(m => m.toString()));
    if (uniqueMembers.size !== members.length) {
        throw new Error('Duplicate members in configuration');
    }

    // Validate threshold
    if (threshold <= 0) {
        throw new Error('Threshold must be greater than 0');
    }

    if (threshold > members.length) {
        throw new Error('Threshold cannot exceed number of members');
    }
}

/**
 * Validates that a signer is authorized to initialize the multisig
 */
export function validateSigner(signer: PublicKey, members: PublicKey[]): boolean {
    return members.some(member => member.equals(signer));
}