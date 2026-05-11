import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { createHash } from "crypto";
import { TransactionMessage, CompiledInstruction } from "./types";

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
