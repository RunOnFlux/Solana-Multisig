"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.INIT_MESSAGE_PREFIX = void 0;
exports.sortMembers = sortMembers;
exports.hashMembers = hashMembers;
exports.deriveMultisigAddress = deriveMultisigAddress;
exports.createInitializationMessage = createInitializationMessage;
exports.createInitSignature = createInitSignature;
exports.verifySignature = verifySignature;
exports.validateConfig = validateConfig;
const web3_js_1 = require("@solana/web3.js");
const crypto_1 = require("crypto");
const nacl = __importStar(require("tweetnacl"));
/**
 * Domain separator for initialization messages
 * Must match the Rust implementation
 */
exports.INIT_MESSAGE_PREFIX = "TRULY_SELF_INITIATING_MULTISIG_INIT";
/**
 * Sort members deterministically (lexicographically by public key bytes)
 * Must match the Rust sorting logic
 */
function sortMembers(members) {
    return [...members].sort((a, b) => {
        const aBytes = a.toBytes();
        const bBytes = b.toBytes();
        for (let i = 0; i < 32; i++) {
            if (aBytes[i] !== bBytes[i]) {
                return aBytes[i] - bBytes[i];
            }
        }
        return 0;
    });
}
/**
 * Hash members using SHA-256
 * Must match the Rust hash_members function
 */
function hashMembers(members) {
    const hasher = (0, crypto_1.createHash)("sha256");
    for (const member of members) {
        hasher.update(member.toBytes());
    }
    return hasher.digest();
}
/**
 * Derive the multisig PDA address
 * Must match the Rust derive_multisig_pda function
 */
function deriveMultisigAddress(members, threshold, programId) {
    const sortedMembers = sortMembers(members);
    const memberHash = hashMembers(sortedMembers);
    // Use first 8 bytes of hash as seed (matches Rust implementation)
    const hashSeed = memberHash.slice(0, 8);
    const [pda, bump] = web3_js_1.PublicKey.findProgramAddressSync([
        Buffer.from("multisig"),
        hashSeed,
        Buffer.from([threshold]),
    ], programId);
    return [pda, bump];
}
/**
 * Create the initialization message that members must sign
 * Must match the Rust create_initialization_message function
 */
function createInitializationMessage(members, threshold) {
    const sortedMembers = sortMembers(members);
    // Start with domain separator
    const parts = [Buffer.from(exports.INIT_MESSAGE_PREFIX)];
    // Add each member's public key
    for (const member of sortedMembers) {
        parts.push(Buffer.from(member.toBytes()));
    }
    // Add threshold
    parts.push(Buffer.from([threshold]));
    return Buffer.concat(parts);
}
/**
 * Create a signature for multisig initialization
 * This is done off-chain by each member with their private key
 */
function createInitSignature(members, threshold, memberKeypair) {
    // Create the message
    const message = createInitializationMessage(members, threshold);
    // Sign with member's private key
    const signature = nacl.sign.detached(message, memberKeypair.secretKey);
    // Hash the message
    const messageHash = (0, crypto_1.createHash)("sha256").update(message).digest();
    return {
        signer: memberKeypair.publicKey,
        signature: Buffer.from(signature),
        messageHash: Buffer.from(messageHash),
    };
}
/**
 * Verify a signature (client-side check, not a replacement for on-chain verification)
 */
function verifySignature(sigData, members, threshold) {
    const message = createInitializationMessage(members, threshold);
    const messageHash = (0, crypto_1.createHash)("sha256").update(message).digest();
    // Verify message hash matches
    if (!messageHash.equals(Buffer.from(sigData.messageHash))) {
        return false;
    }
    // Verify signature
    return nacl.sign.detached.verify(message, sigData.signature, sigData.signer.toBytes());
}
/**
 * Validate multisig configuration
 */
function validateConfig(members, threshold) {
    if (threshold <= 0) {
        throw new Error("Threshold must be greater than 0");
    }
    if (threshold > members.length) {
        throw new Error(`Threshold (${threshold}) cannot exceed number of members (${members.length})`);
    }
    if (members.length === 0) {
        throw new Error("Members array cannot be empty");
    }
    // Check for duplicates
    const uniqueMembers = new Set(members.map(m => m.toString()));
    if (uniqueMembers.size !== members.length) {
        throw new Error("Duplicate members detected");
    }
}
