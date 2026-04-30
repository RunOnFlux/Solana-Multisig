import { PublicKey } from "@solana/web3.js";

/**
 * Signature data for multisig initialization
 * Must match the Rust SignatureData struct
 */
export interface SignatureData {
  /** The member who created this signature */
  signer: PublicKey;
  /** Ed25519 signature (64 bytes) */
  signature: Uint8Array;
  /** SHA-256 hash of the initialization message (32 bytes) */
  messageHash: Uint8Array;
}

/**
 * Multisig configuration
 */
export interface MultisigConfig {
  /** Array of member public keys */
  members: PublicKey[];
  /** Number of required signatures (N-of-M) */
  threshold: number;
  /** Current transaction index */
  transactionIndex: bigint;
  /** Whether the multisig is initialized */
  isInitialized: boolean;
  /** PDA bump seed */
  bump: number;
}

/**
 * VaultTransaction account data.
 * Matches the on-chain VaultTransaction struct.
 */
export interface VaultTransactionData {
  /** Multisig this transaction belongs to */
  multisig: PublicKey;
  /** Transaction index */
  index: bigint;
  /** Member who created the proposal */
  creator: PublicKey;
  /** PDA bump */
  bump: number;
  /** Vault sub-account this proposal targets */
  vaultIndex: number;
  /** Cached vault PDA bump */
  vaultBump: number;
  /** Whether the transaction has been executed */
  executed: boolean;
  /** Members who have approved */
  approvers: PublicKey[];
  /** The compact V0-style transaction message */
  message: TransactionMessage;
}

/**
 * V0-style transaction message stored in a VaultTransaction.
 * Mirrors Solana's MessageV0 minus recent_blockhash and fee_payer.
 */
export interface TransactionMessage {
  /** Total signer count (signer accounts come first in account_keys) */
  numSigners: number;
  /** Number of writable signers */
  numWritableSigners: number;
  /** Number of writable non-signers */
  numWritableNonSigners: number;
  /** Static account keys (multisig PDA must be at index 0) */
  accountKeys: PublicKey[];
  /** Compiled instructions referencing accounts by index */
  instructions: CompiledInstruction[];
  /** Address Lookup Table references */
  addressTableLookups: MessageAddressTableLookup[];
}

/**
 * Compiled instruction format (V0-style).
 * Accounts are referenced by 1-byte index into the combined account list
 * (static account_keys + ALT-loaded writable + ALT-loaded readonly).
 */
export interface CompiledInstruction {
  /** Index of the program in the combined account list */
  programIdIndex: number;
  /** Indices of the instruction's accounts in the combined list */
  accountIndexes: Uint8Array;
  /** Instruction data */
  data: Uint8Array;
}

/**
 * Address Lookup Table reference for compactly loading many accounts.
 */
export interface MessageAddressTableLookup {
  /** The on-chain ALT account address */
  accountKey: PublicKey;
  /** Indices into the ALT pointing to writable accounts */
  writableIndexes: Uint8Array;
  /** Indices into the ALT pointing to readonly accounts */
  readonlyIndexes: Uint8Array;
}

/**
 * Result of multisig initialization
 */
export interface InitializeResult {
  /** Transaction signature */
  signature: string;
  /** Multisig PDA address */
  multisigAddress: PublicKey;
  /** PDA bump seed */
  bump: number;
}

/**
 * Result of transaction creation
 */
export interface CreateTransactionResult {
  /** Transaction signature */
  signature: string;
  /** Transaction PDA address */
  transactionAddress: PublicKey;
  /** Transaction index */
  transactionIndex: bigint;
}
