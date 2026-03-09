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
 * Transaction proposal data
 * Matches the Rust Transaction struct
 */
export interface TransactionData {
  /** Multisig this transaction belongs to */
  multisig: PublicKey;
  /** Transaction index */
  index: bigint;
  /** Instructions to execute */
  instructions: SerializableInstruction[];
  /** Members who have approved */
  approvers: PublicKey[];
  /** Whether the transaction has been executed */
  executed: boolean;
}

/**
 * Serializable instruction format
 */
export interface SerializableInstruction {
  /** Program ID to invoke */
  programId: PublicKey;
  /** Account metas */
  accounts: AccountMeta[];
  /** Instruction data */
  data: Uint8Array;
}

/**
 * Account metadata for instructions
 */
export interface AccountMeta {
  pubkey: PublicKey;
  isSigner: boolean;
  isWritable: boolean;
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

