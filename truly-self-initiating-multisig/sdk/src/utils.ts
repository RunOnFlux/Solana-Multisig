import { PublicKey, Keypair, TransactionInstruction } from "@solana/web3.js";
import { createHash } from "crypto";
import * as nacl from "tweetnacl";
import { SignatureData, TransactionMessage, CompiledInstruction } from "./types";

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
 * PDA seed prefix for vault accounts. Must match VAULT_PDA_SEED in the program.
 */
export const VAULT_PDA_SEED = Buffer.from("vault");

/**
 * Derive a vault PDA owned by SystemProgram (no data) for a given multisig
 * and vault_index. Each multisig can have up to 256 vaults.
 *
 * The vault is the address users send SOL/SPL tokens TO. SystemProgram::transfer
 * from a vault works because the vault is system-owned with empty data.
 */
export function deriveVaultAddress(
  multisig: PublicKey,
  vaultIndex: number,
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [VAULT_PDA_SEED, multisig.toBuffer(), Buffer.from([vaultIndex])],
    programId
  );
}

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

/**
 * Build a V0-style TransactionMessage from raw web3.js TransactionInstructions.
 *
 * The multisig PDA (`vaultPda`) is forced to index 0 as the canonical writable
 * signer. Other accounts are deduplicated and ordered to match Solana's V0
 * convention: writable signers, readonly signers, writable non-signers,
 * readonly non-signers.
 *
 * No ALT support — for ALT-aware proposals, construct the TransactionMessage
 * manually with `addressTableLookups` populated.
 */
export function buildMessageFromInstructions(
  vaultPda: PublicKey,
  instructions: TransactionInstruction[]
): TransactionMessage {
  // Walk every instruction key + every program. Collapse to a unique set with
  // the strongest is_signer / is_writable observed across appearances.
  type Entry = { pubkey: PublicKey; isSigner: boolean; isWritable: boolean };
  const map = new Map<string, Entry>();

  const observe = (pubkey: PublicKey, isSigner: boolean, isWritable: boolean) => {
    const k = pubkey.toBase58();
    const cur = map.get(k);
    if (cur) {
      cur.isSigner = cur.isSigner || isSigner;
      cur.isWritable = cur.isWritable || isWritable;
    } else {
      map.set(k, { pubkey, isSigner, isWritable });
    }
  };

  // Force vault PDA to be the first writable signer.
  observe(vaultPda, true, true);

  for (const ix of instructions) {
    observe(ix.programId, false, false); // program is readonly non-signer
    for (const k of ix.keys) {
      observe(k.pubkey, k.isSigner, k.isWritable);
    }
  }

  // Sort: writable signers first, then readonly signers, then writable non-signers,
  // then readonly non-signers. Within each tier, keep insertion order (Map preserves it).
  const all = Array.from(map.values());
  const writableSigners = all.filter(e => e.isSigner && e.isWritable);
  const readonlySigners = all.filter(e => e.isSigner && !e.isWritable);
  const writableNonSigners = all.filter(e => !e.isSigner && e.isWritable);
  const readonlyNonSigners = all.filter(e => !e.isSigner && !e.isWritable);

  // Make sure vaultPda is actually first within writableSigners (should be by
  // insertion order, but enforce defensively).
  const vaultIndex = writableSigners.findIndex(e => e.pubkey.equals(vaultPda));
  if (vaultIndex > 0) {
    const [vault] = writableSigners.splice(vaultIndex, 1);
    writableSigners.unshift(vault);
  }

  const ordered: Entry[] = [
    ...writableSigners,
    ...readonlySigners,
    ...writableNonSigners,
    ...readonlyNonSigners,
  ];

  const accountKeys = ordered.map(e => e.pubkey);
  const accountIndex = (pubkey: PublicKey): number => {
    const idx = accountKeys.findIndex(k => k.equals(pubkey));
    if (idx < 0) {
      throw new Error(`Account ${pubkey.toBase58()} not found in account_keys`);
    }
    return idx;
  };

  const compiled: CompiledInstruction[] = instructions.map(ix => ({
    programIdIndex: accountIndex(ix.programId),
    accountIndexes: Uint8Array.from(ix.keys.map(k => accountIndex(k.pubkey))),
    data: Uint8Array.from(ix.data),
  }));

  return {
    numSigners: writableSigners.length + readonlySigners.length,
    numWritableSigners: writableSigners.length,
    numWritableNonSigners: writableNonSigners.length,
    accountKeys,
    instructions: compiled,
    addressTableLookups: [],
  };
}
