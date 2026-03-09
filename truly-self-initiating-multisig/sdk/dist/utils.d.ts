import { PublicKey, Keypair } from "@solana/web3.js";
import { SignatureData } from "./types";
/**
 * Domain separator for initialization messages
 * Must match the Rust implementation
 */
export declare const INIT_MESSAGE_PREFIX = "TRULY_SELF_INITIATING_MULTISIG_INIT";
/**
 * Sort members deterministically (lexicographically by public key bytes)
 * Must match the Rust sorting logic
 */
export declare function sortMembers(members: PublicKey[]): PublicKey[];
/**
 * Hash members using SHA-256
 * Must match the Rust hash_members function
 */
export declare function hashMembers(members: PublicKey[]): Buffer;
/**
 * Derive the multisig PDA address
 * Must match the Rust derive_multisig_pda function
 */
export declare function deriveMultisigAddress(members: PublicKey[], threshold: number, programId: PublicKey): [PublicKey, number];
/**
 * Create the initialization message that members must sign
 * Must match the Rust create_initialization_message function
 */
export declare function createInitializationMessage(members: PublicKey[], threshold: number): Buffer;
/**
 * Create a signature for multisig initialization
 * This is done off-chain by each member with their private key
 */
export declare function createInitSignature(members: PublicKey[], threshold: number, memberKeypair: Keypair): SignatureData;
/**
 * Verify a signature (client-side check, not a replacement for on-chain verification)
 */
export declare function verifySignature(sigData: SignatureData, members: PublicKey[], threshold: number): boolean;
/**
 * Validate multisig configuration
 */
export declare function validateConfig(members: PublicKey[], threshold: number): void;
