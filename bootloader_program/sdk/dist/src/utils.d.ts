import { PublicKey } from '@solana/web3.js';
/**
 * Validates that a multisig configuration is valid
 */
export declare function validateMultisigConfig(members: PublicKey[], threshold: number): void;
/**
 * Validates that a signer is authorized to initialize the multisig
 */
export declare function validateSigner(signer: PublicKey, members: PublicKey[]): boolean;
//# sourceMappingURL=utils.d.ts.map