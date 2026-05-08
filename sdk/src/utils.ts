import { PublicKey, Keypair, TransactionInstruction } from "@solana/web3.js";
import { createHash } from "crypto";
import * as nacl from "tweetnacl";
import {
  SignatureData,
  TransactionMessage,
  CompiledInstruction,
} from "./types";

/**
 * Domain separator for initialization messages
 * Must match the Rust implementation
 */
export const INIT_MESSAGE_PREFIX = "SOLANA_MULTISIG_INIT";

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
 * Derive the multisig PDA address.
 * Must byte-for-byte match the Rust `derive_multisig_pda` function.
 *
 * Uses the FULL 32-byte sha256 of sorted members as a seed. Truncating
 * (e.g. to 8 bytes) would let an attacker find a colliding member set
 * with ~2^64 preimage work and steal pre-funded vault balances by
 * initializing the multisig at the colliding PDA before the legitimate
 * users do — vault PDAs are derived from the multisig PDA address (not
 * its contents), so squatting the multisig address means controlling
 * every vault under it.
 */
export function deriveMultisigAddress(
  members: PublicKey[],
  threshold: number,
  programId: PublicKey
): [PublicKey, number] {
  const sortedMembers = sortMembers(members);
  const memberHash = hashMembers(sortedMembers);

  const [pda, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("multisig"), memberHash, Buffer.from([threshold])],
    programId
  );

  return [pda, bump];
}

/**
 * Create the fixed-size init message that members sign off-chain.
 *
 * Layout (53 bytes total, regardless of member count):
 *   [0..20]   domain separator (`INIT_MESSAGE_PREFIX`)
 *   [20..52]  sha256(sorted_members concatenated raw bytes)
 *   [52]      threshold
 *
 * Must byte-for-byte match the Rust `create_initialization_message`.
 */
export function createInitializationMessage(
  members: PublicKey[],
  threshold: number
): Buffer {
  const sortedMembers = sortMembers(members);
  const memberHash = hashMembers(sortedMembers); // 32-byte sha256
  return Buffer.concat([
    Buffer.from(INIT_MESSAGE_PREFIX),
    memberHash,
    Buffer.from([threshold]),
  ]);
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
  const message = createInitializationMessage(members, threshold);
  const signature = nacl.sign.detached(message, memberKeypair.secretKey);

  return {
    signer: memberKeypair.publicKey,
    signature: Buffer.from(signature),
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
    throw new Error(
      `Threshold (${threshold}) cannot exceed number of members (${members.length})`
    );
  }

  if (members.length === 0) {
    throw new Error("Members array cannot be empty");
  }

  // Check for duplicates
  const uniqueMembers = new Set(members.map((m) => m.toString()));
  if (uniqueMembers.size !== members.length) {
    throw new Error("Duplicate members detected");
  }
}

/**
 * Create an Ed25519 program instruction that verifies a SINGLE signature.
 *
 * Kept as a primitive for tests and for callers who want one-sig-per-ix
 * semantics. The init flow uses {@link createBatchedEd25519Instruction}
 * instead — a single ix verifying every signer's signature, which keeps
 * the init transaction under Solana's 1232-byte cap for big multisigs.
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
  instructionData.writeUInt16LE(0xffff, offset);
  offset += 2;

  // Public key offset (2 bytes, little-endian)
  instructionData.writeUInt16LE(pubkeyOffset, offset);
  offset += 2;

  // Public key instruction index (2 bytes, 0xFFFF = same instruction)
  instructionData.writeUInt16LE(0xffff, offset);
  offset += 2;

  // Message data offset (2 bytes, little-endian)
  instructionData.writeUInt16LE(messageOffset, offset);
  offset += 2;

  // Message data size (2 bytes, little-endian)
  instructionData.writeUInt16LE(messageSize, offset);
  offset += 2;

  // Message instruction index (2 bytes, 0xFFFF = same instruction)
  instructionData.writeUInt16LE(0xffff, offset);
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
 * Build a SINGLE Ed25519 native-program instruction that verifies all
 * collected signatures over the shared init message.
 *
 * The Ed25519 ix layout supports `num_signatures > 1` with a per-entry
 * 14-byte header pointing at sig/pubkey/message offsets within the same
 * instruction's data buffer. We pack:
 *   [header (2 + 14*N bytes)]
 *   [signatures (64 * N bytes)]
 *   [pubkeys (32 * N bytes)]
 *   [shared message (M bytes)]
 *
 * Sharing the message bytes (instead of repeating them per signature) is
 * what brings 5+-signer init transactions under Solana's 1232-byte cap.
 *
 * MUST be prepended at instruction index 0 in the init transaction — the
 * on-chain program reads it from the Instructions Sysvar at that index.
 */
export function createBatchedEd25519Instruction(
  signatures: SignatureData[],
  message: Buffer
): TransactionInstruction {
  if (signatures.length === 0) {
    throw new Error("createBatchedEd25519Instruction: signatures is empty");
  }
  // num_signatures is encoded as a u8 in the Ed25519 ix header. Anything
  // larger would silently overflow when written, producing a malformed ix.
  if (signatures.length > 255) {
    throw new Error(
      `createBatchedEd25519Instruction: too many signatures (${signatures.length}), max is 255`
    );
  }
  for (let i = 0; i < signatures.length; i++) {
    if (signatures[i].signature.length !== 64) {
      throw new Error(
        `createBatchedEd25519Instruction: signature[${i}] must be 64 bytes, got ${signatures[i].signature.length}`
      );
    }
  }

  const n = signatures.length;
  const headerSize = 2 + 14 * n;
  const sigsStart = headerSize;
  const pubkeysStart = sigsStart + n * 64;
  const messageStart = pubkeysStart + n * 32;
  const totalSize = messageStart + message.length;

  const data = Buffer.alloc(totalSize);

  data.writeUInt8(n, 0);
  data.writeUInt8(0, 1); // padding

  for (let i = 0; i < n; i++) {
    const entry = 2 + i * 14;
    const sigOffset = sigsStart + i * 64;
    const pubkeyOffset = pubkeysStart + i * 32;

    data.writeUInt16LE(sigOffset, entry);
    data.writeUInt16LE(0xffff, entry + 2); // sig_instruction_index
    data.writeUInt16LE(pubkeyOffset, entry + 4);
    data.writeUInt16LE(0xffff, entry + 6); // pubkey_instruction_index
    data.writeUInt16LE(messageStart, entry + 8);
    data.writeUInt16LE(message.length, entry + 10);
    data.writeUInt16LE(0xffff, entry + 12); // message_instruction_index

    Buffer.from(signatures[i].signature).copy(data, sigOffset);
    Buffer.from(signatures[i].signer.toBytes()).copy(data, pubkeyOffset);
  }

  message.copy(data, messageStart);

  return new TransactionInstruction({
    keys: [],
    programId: ED25519_PROGRAM_ID,
    data,
  });
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

  const observe = (
    pubkey: PublicKey,
    isSigner: boolean,
    isWritable: boolean
  ) => {
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
  const writableSigners = all.filter((e) => e.isSigner && e.isWritable);
  const readonlySigners = all.filter((e) => e.isSigner && !e.isWritable);
  const writableNonSigners = all.filter((e) => !e.isSigner && e.isWritable);
  const readonlyNonSigners = all.filter((e) => !e.isSigner && !e.isWritable);

  // Make sure vaultPda is actually first within writableSigners (should be by
  // insertion order, but enforce defensively).
  const vaultIndex = writableSigners.findIndex((e) =>
    e.pubkey.equals(vaultPda)
  );
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

  const accountKeys = ordered.map((e) => e.pubkey);
  const accountIndex = (pubkey: PublicKey): number => {
    const idx = accountKeys.findIndex((k) => k.equals(pubkey));
    if (idx < 0) {
      throw new Error(`Account ${pubkey.toBase58()} not found in account_keys`);
    }
    return idx;
  };

  const compiled: CompiledInstruction[] = instructions.map((ix) => ({
    programIdIndex: accountIndex(ix.programId),
    accountIndexes: Uint8Array.from(ix.keys.map((k) => accountIndex(k.pubkey))),
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
