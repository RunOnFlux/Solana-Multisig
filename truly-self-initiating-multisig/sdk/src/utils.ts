import { PublicKey, Keypair, TransactionInstruction } from "@solana/web3.js";
import { createHash } from "crypto";
import * as nacl from "tweetnacl";
import { SignatureData } from "./types";

/**
 * Domain separator for initialization messages
 * Must match the Rust implementation
 */
export const INIT_MESSAGE_PREFIX = "TRULY_SELF_INITIATING_MULTISIG_INIT";

/**
 * Ed25519 Program ID (native Solana program)
 */
export const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111"
);

/**
 * Sort members deterministically (lexicographically by public key bytes)
 * Must match the Rust sorting logic
 */
export function sortMembers(members: PublicKey[]): PublicKey[] {
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
export function hashMembers(members: PublicKey[]): Buffer {
  const hasher = createHash("sha256");
  for (const member of members) {
    hasher.update(member.toBytes());
  }
  return hasher.digest();
}

/**
 * Derive the multisig PDA address
 * Must match the Rust derive_multisig_pda function
 */
export function deriveMultisigAddress(
  members: PublicKey[],
  threshold: number,
  programId: PublicKey
): [PublicKey, number] {
  const sortedMembers = sortMembers(members);
  const memberHash = hashMembers(sortedMembers);

  // Use first 8 bytes of hash as seed (matches Rust implementation)
  const hashSeed = memberHash.slice(0, 8);

  const [pda, bump] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("multisig"),
      hashSeed,
      Buffer.from([threshold]),
    ],
    programId
  );

  return [pda, bump];
}

/**
 * Create the initialization message that members must sign
 * Must match the Rust create_initialization_message function
 */
export function createInitializationMessage(
  members: PublicKey[],
  threshold: number
): Buffer {
  const sortedMembers = sortMembers(members);

  // Start with domain separator
  const parts: Buffer[] = [Buffer.from(INIT_MESSAGE_PREFIX)];

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
export function createInitSignature(
  members: PublicKey[],
  threshold: number,
  memberKeypair: Keypair
): SignatureData {
  // Create the message
  const message = createInitializationMessage(members, threshold);

  // Sign with member's private key
  const signature = nacl.sign.detached(message, memberKeypair.secretKey);

  // Hash the message
  const messageHash = createHash("sha256").update(message).digest();

  return {
    signer: memberKeypair.publicKey,
    signature: Buffer.from(signature),
    messageHash: Buffer.from(messageHash),
  };
}

/**
 * Verify a signature (client-side check, not a replacement for on-chain verification)
 */
export function verifySignature(
  sigData: SignatureData,
  members: PublicKey[],
  threshold: number
): boolean {
  const message = createInitializationMessage(members, threshold);
  const messageHash = createHash("sha256").update(message).digest();

  // Verify message hash matches
  if (!messageHash.equals(Buffer.from(sigData.messageHash))) {
    return false;
  }

  // Verify signature
  return nacl.sign.detached.verify(
    message,
    sigData.signature,
    sigData.signer.toBytes()
  );
}

/**
 * Validate multisig configuration
 */
export function validateConfig(members: PublicKey[], threshold: number): void {
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

/**
 * Create an Ed25519 program instruction for signature verification
 * This instruction must be included BEFORE the initialize_multisig instruction
 * in the same transaction.
 *
 * The Ed25519 program verifies the signature, and our program reads the
 * instruction data via the Instructions Sysvar to confirm verification.
 */
export function createEd25519Instruction(
  pubkey: PublicKey,
  message: Buffer,
  signature: Buffer
): TransactionInstruction {
  // Ed25519 instruction data format:
  // - 1 byte: number of signatures (1)
  // - 1 byte: padding (0)
  // - 2 bytes: signature offset
  // - 2 bytes: signature instruction index (0xFFFF = same instruction)
  // - 2 bytes: public key offset
  // - 2 bytes: public key instruction index (0xFFFF = same instruction)
  // - 2 bytes: message data offset
  // - 2 bytes: message data size
  // - 2 bytes: message instruction index (0xFFFF = same instruction)
  // Then the actual data: signature (64 bytes), pubkey (32 bytes), message

  const numSignatures = 1;
  const padding = 0;

  // Header size: 2 bytes + 14 bytes per signature = 16 bytes
  const headerSize = 2 + 14 * numSignatures;

  // Offsets (after the header)
  const signatureOffset = headerSize;
  const pubkeyOffset = signatureOffset + 64;
  const messageOffset = pubkeyOffset + 32;
  const messageSize = message.length;

  // Build the instruction data
  const instructionData = Buffer.alloc(headerSize + 64 + 32 + message.length);

  let offset = 0;

  // Number of signatures (1 byte)
  instructionData.writeUInt8(numSignatures, offset);
  offset += 1;

  // Padding (1 byte)
  instructionData.writeUInt8(padding, offset);
  offset += 1;

  // Signature offset (2 bytes, little-endian)
  instructionData.writeUInt16LE(signatureOffset, offset);
  offset += 2;

  // Signature instruction index (2 bytes, 0xFFFF = same instruction)
  instructionData.writeUInt16LE(0xFFFF, offset);
  offset += 2;

  // Public key offset (2 bytes, little-endian)
  instructionData.writeUInt16LE(pubkeyOffset, offset);
  offset += 2;

  // Public key instruction index (2 bytes, 0xFFFF = same instruction)
  instructionData.writeUInt16LE(0xFFFF, offset);
  offset += 2;

  // Message data offset (2 bytes, little-endian)
  instructionData.writeUInt16LE(messageOffset, offset);
  offset += 2;

  // Message data size (2 bytes, little-endian)
  instructionData.writeUInt16LE(messageSize, offset);
  offset += 2;

  // Message instruction index (2 bytes, 0xFFFF = same instruction)
  instructionData.writeUInt16LE(0xFFFF, offset);
  offset += 2;

  // Signature (64 bytes)
  signature.copy(instructionData, signatureOffset);

  // Public key (32 bytes)
  Buffer.from(pubkey.toBytes()).copy(instructionData, pubkeyOffset);

  // Message
  message.copy(instructionData, messageOffset);

  return new TransactionInstruction({
    keys: [],
    programId: ED25519_PROGRAM_ID,
    data: instructionData,
  });
}

/**
 * Create Ed25519 verification instructions for all signatures
 * These must be prepended to the transaction before the initialize instruction
 */
export function createEd25519Instructions(
  members: PublicKey[],
  threshold: number,
  signatures: SignatureData[]
): TransactionInstruction[] {
  const message = createInitializationMessage(members, threshold);

  return signatures.map(sig =>
    createEd25519Instruction(sig.signer, message, Buffer.from(sig.signature))
  );
}
