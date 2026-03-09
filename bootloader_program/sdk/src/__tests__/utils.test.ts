/**
 * Tests for utility functions
 */

import { PublicKey } from '@solana/web3.js';
import { expect } from 'chai';
import {
    computeConfigHash,
    deriveMultisigAddresses,
    validateMultisigConfig,
    validateSigner,
} from '../utils';

describe('Utility Functions', () => {
    // Use valid Solana public keys for testing
    const mockMembers = [
        new PublicKey('11111111111111111111111111111111'), // System program
        new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'), // Token program
        new PublicKey('SysvarRent111111111111111111111111111111111'), // Rent sysvar
    ];

    describe('computeConfigHash', () => {
        it('should produce consistent hashes for same configuration', () => {
            const hash1 = computeConfigHash(mockMembers, 2);
            const hash2 = computeConfigHash(mockMembers, 2);

            expect(hash1).to.deep.equal(hash2);
        });

        it('should produce different hashes for different configurations', () => {
            const hash1 = computeConfigHash(mockMembers, 2);
            const hash2 = computeConfigHash(mockMembers, 3);

            expect(hash1).to.not.deep.equal(hash2);
        });

        it('should be order-independent for members', () => {
            const shuffledMembers = [mockMembers[2], mockMembers[0], mockMembers[1]];

            const hash1 = computeConfigHash(mockMembers, 2);
            const hash2 = computeConfigHash(shuffledMembers, 2);

            expect(hash1).to.deep.equal(hash2);
        });

        it('should include salt in hash calculation', () => {
            const salt = [1, 2, 3, 4];

            const hash1 = computeConfigHash(mockMembers, 2);
            const hash2 = computeConfigHash(mockMembers, 2, salt);

            expect(hash1).to.not.deep.equal(hash2);
        });
    });

    describe('deriveMultisigAddresses', () => {
        it('should derive consistent addresses for same configuration', () => {
            const result1 = deriveMultisigAddresses(mockMembers, 2);
            const result2 = deriveMultisigAddresses(mockMembers, 2);

            expect(result1.createKey.equals(result2.createKey)).to.be.true;
            expect(result1.multisig.equals(result2.multisig)).to.be.true;
            expect(result1.configHash).to.deep.equal(result2.configHash);
        });

        it('should derive different addresses for different configurations', () => {
            const result1 = deriveMultisigAddresses(mockMembers, 2);
            const result2 = deriveMultisigAddresses(mockMembers, 3);

            expect(result1.createKey.equals(result2.createKey)).to.be.false;
            expect(result1.multisig.equals(result2.multisig)).to.be.false;
        });
    });

    describe('validateMultisigConfig', () => {
        it('should accept valid configurations', () => {
            expect(() => validateMultisigConfig(mockMembers, 2)).to.not.throw();
            expect(() => validateMultisigConfig(mockMembers, 1)).to.not.throw();
            expect(() => validateMultisigConfig(mockMembers, 3)).to.not.throw();
        });

        it('should reject invalid threshold', () => {
            expect(() => validateMultisigConfig(mockMembers, 0)).to.throw('Threshold must be greater than 0');
            expect(() => validateMultisigConfig(mockMembers, 4)).to.throw('Threshold cannot exceed number of members');
        });

        it('should reject duplicate members', () => {
            const duplicateMembers = [mockMembers[0], mockMembers[0], mockMembers[1]];

            expect(() => validateMultisigConfig(duplicateMembers, 2)).to.throw('Duplicate members in configuration');
        });

        it('should reject empty members array', () => {
            expect(() => validateMultisigConfig([], 1)).to.throw('At least one member is required');
        });

        it('should reject too many members', () => {
            const tooManyMembers = Array(11).fill(0).map(() => {
                // Generate random valid public keys
                const keypair = require('@solana/web3.js').Keypair.generate();
                return keypair.publicKey;
            });

            expect(() => validateMultisigConfig(tooManyMembers, 5)).to.throw('Maximum 10 members allowed');
        });
    });

    describe('validateSigner', () => {
        it('should accept valid signers', () => {
            expect(validateSigner(mockMembers[0], mockMembers)).to.be.true;
            expect(validateSigner(mockMembers[1], mockMembers)).to.be.true;
            expect(validateSigner(mockMembers[2], mockMembers)).to.be.true;
        });

        it('should reject invalid signers', () => {
            const invalidSigner = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'); // Another valid key

            expect(validateSigner(invalidSigner, mockMembers)).to.be.false;
        });
    });
});

// Integration test helpers
export const createMockMembers = (count: number): PublicKey[] => {
    return Array(count).fill(0).map(() => {
        // Generate random valid public keys for testing
        const { Keypair } = require('@solana/web3.js');
        return Keypair.generate().publicKey;
    });
};

export const createTestConfig = () => ({
    members: createMockMembers(3),
    threshold: 2,
    salt: undefined as number[] | undefined,
});