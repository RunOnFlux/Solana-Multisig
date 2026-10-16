/**
 * Pure, offline, Anchor-free decoder for SSP Solana Multisig vault
 * transactions.
 *
 * SELF-CONTAINED BY DESIGN: this module deliberately imports nothing from the
 * rest of the SDK (no ./types, no ./utils, no @coral-xyz/anchor, no
 * @solana/spl-token, no crypto) so downstream repos can vendor (copy) this
 * single file verbatim. The only runtime dependencies are `PublicKey` /
 * `SystemProgram` / `Transaction` from `@solana/web3.js` and `Buffer`.
 *
 * Purpose: co-signer devices (ssp-wallet, ssp-key) and the relay builder use
 * this to independently verify — from the exact raw bytes being ed25519
 * partial-signed — what a relay-supplied vault bundle actually does:
 * which outer instructions the leaf key authorizes, and which recipients /
 * amounts / mint the inner `create_transaction` message moves funds to.
 * A successful decode that contradicts the relay-supplied display payload is
 * an active-attack indicator.
 *
 * The decoders NEVER throw — any parse failure returns
 * `{ kind: "undecodable", error }`. Callers MUST treat "undecodable" as a
 * hard block (refuse to sign): a relay can deliberately produce bytes that
 * are valid on-chain but undecodable here (e.g. two create_transaction
 * instructions).
 *
 * Entry points:
 *  - decodeVaultSolanaTransaction + compareDecodedToExpected — enterprise
 *    bundles (create path, and the approve-only path's outer checks).
 *  - fetchAndDecodeProposal / decodeVaultTransactionAccount +
 *    compareProposalToExpected — the on-chain VaultTransaction behind an
 *    approve-only (split-flow) request.
 *  - verifyApproveOnlyTransaction — the whole approve-only gate in one call.
 *  - verifyConsumerSolanaBundle — fail-closed gate for the consumer 2-of-2
 *    send bundle (wallet → key).
 */

import { PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { Buffer } from "buffer";

// ---------------------------------------------------------------------------
// Instruction discriminators — copied verbatim from
// sdk/src/idl/solana_multisig.json (Anchor sighash = sha256("global:<name>")[..8]).
// Hardcoded so the decoder needs NO runtime hashing (avoids crypto shims in
// React Native / browser bundles).
// ---------------------------------------------------------------------------

export const CREATE_TRANSACTION_DISCRIMINATOR = Uint8Array.from([
  227, 193, 53, 239, 55, 126, 112, 105,
]);
export const APPROVE_TRANSACTION_DISCRIMINATOR = Uint8Array.from([
  224, 39, 88, 181, 36, 59, 155, 122,
]);
export const EXECUTE_TRANSACTION_DISCRIMINATOR = Uint8Array.from([
  231, 173, 49, 91, 235, 24, 68, 19,
]);
export const CLOSE_TRANSACTION_DISCRIMINATOR = Uint8Array.from([
  97, 46, 152, 170, 42, 215, 192, 218,
]);

/** Anchor account discriminator of `VaultTransaction` (sha256("account:VaultTransaction")[..8]). */
export const VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR = Uint8Array.from([
  168, 250, 162, 100, 81, 14, 162, 207,
]);

// ---------------------------------------------------------------------------
// Well-known program ids (hardcoded so the decoder does not depend on
// @solana/spl-token — ssp-key does not ship it).
// ---------------------------------------------------------------------------

export const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
);
export const TOKEN_2022_PROGRAM_ID = new PublicKey(
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
);
export const ATA_PROGRAM_ID = new PublicKey(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
);
export const COMPUTE_BUDGET_PROGRAM_ID = new PublicKey(
  "ComputeBudget111111111111111111111111111111"
);
/** SPL Memo v2. Memo v1 and any other memo program are NOT recognized. */
export const MEMO_PROGRAM_ID = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

/**
 * Hand-rolled Associated Token Account derivation (identical to
 * @solana/spl-token's getAssociatedTokenAddressSync, minus the dependency).
 */
export function deriveAssociatedTokenAddress(
  owner: PublicKey,
  mint: PublicKey,
  tokenProgramId: PublicKey = TOKEN_PROGRAM_ID
): PublicKey {
  const [ata] = PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgramId.toBuffer(), mint.toBuffer()],
    ATA_PROGRAM_ID
  );
  return ata;
}

/** Vault PDA = findProgramAddress(["vault", multisig, [vaultIndex]], programId). */
function deriveVaultPda(
  multisig: PublicKey,
  vaultIndex: number,
  programId: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), multisig.toBuffer(), Buffer.from([vaultIndex])],
    programId
  )[0];
}

/** Proposal PDA = findProgramAddress(["transaction", multisig, index u64 LE], programId). */
function deriveTransactionPda(
  multisig: PublicKey,
  transactionIndex: bigint,
  programId: PublicKey
): PublicKey {
  const index = Buffer.alloc(8);
  index.writeBigUInt64LE(transactionIndex);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("transaction"), multisig.toBuffer(), index],
    programId
  )[0];
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface DecodedSolanaVaultRecipient {
  /** Recipient owner when ataVerified, else the raw destination account. */
  address: string;
  /** Raw destination token account (SPL transfers only). */
  ata?: string;
  /**
   * true  = `ata` equals the derived ATA of `opts.expectedRecipientOwner`
   *         for `opts.expectedMint` (address is the owner);
   * false = derivation did NOT match (address is the raw ata);
   * undefined = verification not attempted (no opts / native transfer).
   */
  ataVerified?: boolean;
  /** Amount in base units (lamports for native, token base units for SPL). */
  amount: string;
  asset: "native" | "spl";
  /**
   * Token mint, from the signed TransferChecked bytes. Always present for
   * "spl" recipients: legacy SPL Transfer (tag 3), which carries no mint, is
   * no longer accepted as a recipient (counted as an unknown instruction).
   */
  mint?: string;
  /**
   * Token decimals, from the signed TransferChecked bytes (the token program
   * rejects the transfer on-chain if they differ from the mint's decimals).
   * The ONLY trustworthy decimals source besides the device's own token list.
   */
  decimals?: number;
  /** Token program that executes the transfer (Token or Token-2022). */
  tokenProgram?: string;
}

export type DecodedVaultSolanaTx =
  | {
      kind: "create";
      vaultIndex: number;
      multisigPda: string;
      transactionPda: string;
      creator: string;
      /** Inner message account_keys[0] — by convention the vault PDA. */
      sender: string;
      recipients: DecodedSolanaVaultRecipient[];
      /**
       * Sum of inner native transfers from the vault to the fee payer
       * (reimbursements). NOT a recipient — `compareDecodedToExpected` bounds
       * this against `maxFeeLamports` (default 0) so it can no longer hide an
       * unbounded vault drain routed to the fee payer.
       */
      feeLamports: string;
      /** The outer transaction fee payer (destination of `feeLamports`), or null. */
      feePayer: string | null;
      approvers: string[];
      /** Proposal PDA each bundled `approve_transaction` targets (keys[1]). */
      approveTargets: string[];
      /** Proposal PDA each bundled `execute_transaction` targets (keys[1]). */
      executeTargets: string[];
      /** Inner instructions the decoder could not classify (fail-closed). */
      unknownInnerInstructionCount: number;
      /** Outer instructions outside the allowlist — leaf-key-drain guard. */
      unknownOuterPrograms: string[];
      /** SPL Memo v2 texts (only when `opts.allowMemo`; otherwise memos are unknown). */
      memos?: string[];
    }
  | {
      kind: "approve";
      multisigPda: string;
      transactionPda: string;
      approvers: string[];
      /** Proposal PDA each `approve_transaction` targets (keys[1]). */
      approveTargets: string[];
      /** Multisig account each `approve_transaction` names (keys[0]). */
      approveMultisigs?: string[];
      /** transaction_index argument of the first approve (u64, decimal), or null. */
      transactionIndex?: string | null;
      unknownOuterPrograms: string[];
    }
  | { kind: "undecodable"; error: string };

/** Options for {@link decodeVaultSolanaTransaction}. */
export interface DecodeVaultSolanaOptions {
  expectedRecipientOwner?: string;
  expectedMint?: string;
  /**
   * Accept outer ComputeBudget SetComputeUnitLimit / SetComputeUnitPrice
   * instructions (at most one of each) within these caps. The priority fee is
   * charged to the transaction FEE PAYER, so callers should also require the
   * fee payer to be the paymaster (expectedFeePayer). Default: ComputeBudget
   * instructions are reported in `unknownOuterPrograms` (fail closed).
   */
  allowComputeBudget?: {
    maxUnitLimit?: number;
    maxUnitPriceMicroLamports?: string | number | bigint;
  };
  /**
   * Accept inner SPL Memo v2 instructions that reference no accounts and carry
   * valid UTF-8; their text is returned in `memos`. Default: counted as
   * unknown inner instructions (fail closed).
   */
  allowMemo?: boolean;
}

// ---------------------------------------------------------------------------
// Internal byte helpers
// ---------------------------------------------------------------------------

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function readU64LE(buf: Buffer, offset: number): bigint {
  if (offset + 8 > buf.length) {
    throw new Error("u64 read past end of buffer");
  }
  let value = BigInt(0);
  for (let i = 7; i >= 0; i--) {
    value = (value << BigInt(8)) | BigInt(buf[offset + i]);
  }
  return value;
}

/** Strict UTF-8 decode (no replacement characters, no control characters). */
function decodeUtf8Strict(data: Buffer): string | null {
  const text = data.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(data)) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) return null;
  return text;
}

/** Sequential borsh reader with strict bounds checking. */
class ByteReader {
  private offset = 0;

  constructor(private readonly buf: Buffer) {}

  private ensure(n: number): void {
    if (this.offset + n > this.buf.length) {
      throw new Error(
        `truncated data: need ${n} byte(s) at offset ${this.offset}, have ${this.buf.length}`
      );
    }
  }

  u8(): number {
    this.ensure(1);
    return this.buf[this.offset++];
  }

  u32(): number {
    this.ensure(4);
    const v = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  u64(): bigint {
    this.ensure(8);
    const v = readU64LE(this.buf, this.offset);
    this.offset += 8;
    return v;
  }

  bool(): boolean {
    const v = this.u8();
    if (v > 1) throw new Error(`invalid bool byte ${v}`);
    return v === 1;
  }

  bytes(n: number): Buffer {
    this.ensure(n);
    const b = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return b;
  }

  pubkey(): PublicKey {
    return new PublicKey(this.bytes(32));
  }
}

interface InnerCompiledInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Buffer;
}

interface InnerMessage {
  vaultIndex: number;
  accountKeys: PublicKey[];
  instructions: InnerCompiledInstruction[];
  addressTableLookupCount: number;
}

/**
 * Parse a borsh `TransactionMessage` (shared by the create_transaction
 * instruction data and the on-chain VaultTransaction account):
 *   [0]      num_signers: u8
 *   [1]      num_writable_signers: u8
 *   [2]      num_writable_non_signers: u8
 *   u32-LE   account_keys length, then N x 32-byte pubkeys
 *   u32-LE   instruction count, then per instruction:
 *              u8 program_id_index,
 *              u32-LE account_indexes length + bytes,
 *              u32-LE data length + bytes
 *   u32-LE   address_table_lookups length, then per lookup:
 *              32-byte account_key, u32-LE + writable bytes, u32-LE + readonly bytes
 */
function parseTransactionMessage(
  reader: ByteReader,
  vaultIndex: number
): InnerMessage {
  reader.u8(); // num_signers
  reader.u8(); // num_writable_signers
  reader.u8(); // num_writable_non_signers

  const accountKeyCount = reader.u32();
  const accountKeys: PublicKey[] = [];
  for (let i = 0; i < accountKeyCount; i++) {
    accountKeys.push(reader.pubkey());
  }

  const instructionCount = reader.u32();
  const instructions: InnerCompiledInstruction[] = [];
  for (let i = 0; i < instructionCount; i++) {
    const programIdIndex = reader.u8();
    const accountIndexesLen = reader.u32();
    const accountIndexes = Array.from(reader.bytes(accountIndexesLen));
    const dataLen = reader.u32();
    const ixData = Buffer.from(reader.bytes(dataLen));
    instructions.push({ programIdIndex, accountIndexes, data: ixData });
  }

  const addressTableLookupCount = reader.u32();
  for (let i = 0; i < addressTableLookupCount; i++) {
    reader.bytes(32); // account_key
    reader.bytes(reader.u32()); // writable_indexes
    reader.bytes(reader.u32()); // readonly_indexes
  }

  return { vaultIndex, accountKeys, instructions, addressTableLookupCount };
}

/**
 * Parse `create_transaction` instruction data. Borsh layout verified against
 * sdk/src/idl/solana_multisig.json:
 *   [0..8)   discriminator
 *   [8]      vault_index: u8
 *   ...      TransactionMessage (see parseTransactionMessage)
 */
function parseCreateTransactionData(data: Buffer): InnerMessage {
  const reader = new ByteReader(data);
  reader.bytes(8); // discriminator (already matched by caller)
  const vaultIndex = reader.u8();
  return parseTransactionMessage(reader, vaultIndex);
}

// ---------------------------------------------------------------------------
// Inner message classification (shared by bundle and on-chain proposal decode)
// ---------------------------------------------------------------------------

const SYSTEM_IX_TAG_TRANSFER = 2;
const SYSTEM_IX_TAG_NONCE_ADVANCE = 4;
const SPL_IX_TAG_TRANSFER_CHECKED = 12;
const COMPUTE_BUDGET_TAG_SET_UNIT_LIMIT = 2;
const COMPUTE_BUDGET_TAG_SET_UNIT_PRICE = 3;

interface InnerClassification {
  recipients: DecodedSolanaVaultRecipient[];
  feeLamports: bigint;
  unknownInnerInstructionCount: number;
  memos: string[];
}

/**
 * Classify every inner instruction of a vault TransactionMessage.
 *
 * Recognized (everything else is counted as unknown — fail closed):
 *  - SystemProgram transfer FROM the vault (account_keys[0]); transfers to
 *    `feePayer` are bucketed as fee reimbursement, the rest are recipients;
 *  - SPL Token / Token-2022 TransferChecked AUTHORIZED by the vault: mint and
 *    decimals come from the signed bytes;
 *  - SPL Memo v2 with no accounts and valid UTF-8 (only when `allowMemo`).
 *
 * Legacy SPL `Transfer` (tag 3) is deliberately NOT recognized: it carries no
 * mint, so the token being moved cannot be bound to what is displayed (an
 * attacker could move USDC while the screen says "BONK"). Both SSP builders
 * emit TransferChecked only.
 */
function classifyInnerMessage(
  inner: InnerMessage,
  feePayer: string | undefined,
  allowMemo: boolean
): InnerClassification {
  if (inner.accountKeys.length === 0) {
    throw new Error("vault transaction message has no account keys");
  }
  const resolve = (index: number): PublicKey => {
    const key = inner.accountKeys[index];
    if (!key) {
      throw new Error(
        `inner account index ${index} out of bounds (${inner.accountKeys.length} static keys)`
      );
    }
    return key;
  };

  const recipients: DecodedSolanaVaultRecipient[] = [];
  let feeLamports = BigInt(0);
  const memos: string[] = [];
  // ALT-loaded accounts are not resolvable offline — count each lookup
  // as unclassifiable so callers fail closed.
  let unknownInnerInstructionCount = inner.addressTableLookupCount;

  for (const cix of inner.instructions) {
    try {
      const prog = resolve(cix.programIdIndex);
      const d = cix.data;
      const isTokenProgram =
        prog.equals(TOKEN_PROGRAM_ID) || prog.equals(TOKEN_2022_PROGRAM_ID);

      if (
        prog.equals(SystemProgram.programId) &&
        d.length === 12 &&
        d.readUInt32LE(0) === SYSTEM_IX_TAG_TRANSFER &&
        cix.accountIndexes.length >= 2
      ) {
        // SystemProgram transfer: accounts [from, to].
        const source = resolve(cix.accountIndexes[0]);
        const dest = resolve(cix.accountIndexes[1]).toBase58();
        const amount = readU64LE(d, 4);
        // Only the vault (account_keys[0]) can be debited here — it is the
        // sole invoke_signed signer at execute, so a native transfer whose
        // SOURCE is not the vault would fail on-chain. Treat any non-vault
        // source as unclassifiable (fail-closed) rather than trusting its
        // destination/amount — this stops a transfer being mislabeled as a
        // vault outflow (or fee) when it isn't one.
        if (!source.equals(inner.accountKeys[0])) {
          unknownInnerInstructionCount++;
        } else if (feePayer && dest === feePayer) {
          // Vault -> fee payer: a reimbursement, bucketed separately. This
          // is BOUNDED by the compare functions (maxFeeLamports), so it can
          // not smuggle an unbounded vault drain to the fee payer.
          feeLamports += amount;
        } else {
          recipients.push({
            address: dest,
            amount: amount.toString(),
            asset: "native",
          });
        }
      } else if (
        isTokenProgram &&
        d.length === 10 &&
        d[0] === SPL_IX_TAG_TRANSFER_CHECKED &&
        cix.accountIndexes.length >= 4
      ) {
        // TransferChecked: accounts [source, mint, dest, authority];
        // data [tag u8, amount u64, decimals u8].
        // The AUTHORITY (accountIndexes[3]) must be the vault — the vault
        // PDA is the only invoke_signed signer at execute, so a transfer
        // authorized by anyone else debits a NON-vault token account (e.g.
        // a member leaf's own). Mirror the native source==vault guard and
        // fail closed rather than mis-attributing it as a vault outflow.
        if (!resolve(cix.accountIndexes[3]).equals(inner.accountKeys[0])) {
          unknownInnerInstructionCount++;
        } else {
          const dest = resolve(cix.accountIndexes[2]).toBase58();
          recipients.push({
            address: dest,
            ata: dest,
            amount: readU64LE(d, 1).toString(),
            asset: "spl",
            mint: resolve(cix.accountIndexes[1]).toBase58(),
            decimals: d[9],
            tokenProgram: prog.toBase58(),
          });
        }
      } else if (
        allowMemo &&
        prog.equals(MEMO_PROGRAM_ID) &&
        cix.accountIndexes.length === 0
      ) {
        const text = decodeUtf8Strict(d);
        if (text === null) {
          unknownInnerInstructionCount++;
        } else {
          memos.push(text);
        }
      } else {
        // Includes legacy SPL Transfer (tag 3): no mint on the wire.
        unknownInnerInstructionCount++;
      }
    } catch {
      unknownInnerInstructionCount++;
    }
  }

  return { recipients, feeLamports, unknownInnerInstructionCount, memos };
}

/** Resolve SPL recipients' ATAs to `owner` when they are its ATA for `mint`. */
function resolveAtaOwner(
  recipients: DecodedSolanaVaultRecipient[],
  ownerBase58: string,
  mintBase58: string
): void {
  const owner = new PublicKey(ownerBase58);
  const mint = new PublicKey(mintBase58);
  const candidates = [
    deriveAssociatedTokenAddress(owner, mint, TOKEN_PROGRAM_ID).toBase58(),
    deriveAssociatedTokenAddress(owner, mint, TOKEN_2022_PROGRAM_ID).toBase58(),
  ];
  for (const r of recipients) {
    if (r.asset !== "spl" || !r.ata) continue;
    if (candidates.includes(r.ata)) {
      r.address = owner.toBase58();
      r.ataVerified = true;
    } else {
      r.address = r.ata;
      r.ataVerified = false;
    }
  }
}

// ---------------------------------------------------------------------------
// Outer bundle parsing (shared by the enterprise and consumer gates)
// ---------------------------------------------------------------------------

interface ParsedComputeBudget {
  tag: number;
  value: bigint | null;
}

interface ParsedAtaCreate {
  index: number;
  funder?: string;
  ata?: string;
  owner?: string;
  mint?: string;
  tokenProgram?: string;
  /** data is create (empty / [0]) or createIdempotent ([1]) */
  dataOk: boolean;
}

interface ParsedMultisigIx {
  index: number;
  keys: PublicKey[];
  data: Buffer;
}

interface ParsedBundle {
  feePayer?: string;
  nonceAdvanceIndexes: number[];
  computeBudget: Array<ParsedComputeBudget & { index: number }>;
  ataCreates: ParsedAtaCreate[];
  creates: Array<ParsedMultisigIx & { inner: InnerMessage }>;
  approves: ParsedMultisigIx[];
  executes: ParsedMultisigIx[];
  closes: ParsedMultisigIx[];
  /**
   * Outer instructions that are never allowed: other programs, SystemProgram
   * instructions other than nonceAdvance, unknown multisig discriminators.
   */
  foreign: Array<{ index: number; programId: string }>;
}

function parseBundle(
  serializedTxBase64: string,
  programId: PublicKey
): ParsedBundle {
  const raw = Buffer.from(serializedTxBase64, "base64");
  if (raw.length === 0) {
    throw new Error("empty transaction bytes");
  }
  const tx = Transaction.from(raw);
  const parsed: ParsedBundle = {
    feePayer: tx.feePayer ? tx.feePayer.toBase58() : undefined,
    nonceAdvanceIndexes: [],
    computeBudget: [],
    ataCreates: [],
    creates: [],
    approves: [],
    executes: [],
    closes: [],
    foreign: [],
  };

  tx.instructions.forEach((ix, index) => {
    const pid = ix.programId;
    const data = Buffer.from(ix.data);
    const keys = ix.keys.map((k) => k.pubkey);

    if (pid.equals(SystemProgram.programId)) {
      // Only nonceAdvance is an allowed outer SystemProgram instruction.
      if (
        data.length >= 4 &&
        data.readUInt32LE(0) === SYSTEM_IX_TAG_NONCE_ADVANCE
      ) {
        parsed.nonceAdvanceIndexes.push(index);
      } else {
        parsed.foreign.push({ index, programId: pid.toBase58() });
      }
    } else if (pid.equals(COMPUTE_BUDGET_PROGRAM_ID)) {
      let value: bigint | null = null;
      const tag = data.length > 0 ? data[0] : -1;
      if (tag === COMPUTE_BUDGET_TAG_SET_UNIT_LIMIT && data.length === 5) {
        value = BigInt(data.readUInt32LE(1));
      } else if (
        tag === COMPUTE_BUDGET_TAG_SET_UNIT_PRICE &&
        data.length === 9
      ) {
        value = readU64LE(data, 1);
      }
      parsed.computeBudget.push({ index, tag, value });
    } else if (pid.equals(ATA_PROGRAM_ID)) {
      // create: [funder, ata, owner, mint, system, tokenProgram]
      parsed.ataCreates.push({
        index,
        funder: keys[0]?.toBase58(),
        ata: keys[1]?.toBase58(),
        owner: keys[2]?.toBase58(),
        mint: keys[3]?.toBase58(),
        tokenProgram: keys[5]?.toBase58(),
        dataOk:
          data.length === 0 ||
          (data.length === 1 && (data[0] === 0 || data[0] === 1)),
      });
    } else if (pid.equals(programId)) {
      const disc = Uint8Array.from(data.subarray(0, 8));
      if (bytesEqual(disc, CREATE_TRANSACTION_DISCRIMINATOR)) {
        parsed.creates.push({
          index,
          keys,
          data,
          inner: parseCreateTransactionData(data),
        });
      } else if (bytesEqual(disc, APPROVE_TRANSACTION_DISCRIMINATOR)) {
        parsed.approves.push({ index, keys, data });
      } else if (bytesEqual(disc, EXECUTE_TRANSACTION_DISCRIMINATOR)) {
        parsed.executes.push({ index, keys, data });
      } else if (bytesEqual(disc, CLOSE_TRANSACTION_DISCRIMINATOR)) {
        parsed.closes.push({ index, keys, data });
      } else {
        // Multisig program with an unrecognized discriminator — fail closed.
        parsed.foreign.push({ index, programId: pid.toBase58() });
      }
    } else {
      parsed.foreign.push({ index, programId: pid.toBase58() });
    }
  });

  return parsed;
}

/** transaction_index argument (u64 LE after the discriminator), or null. */
function readTransactionIndexArg(data: Buffer): bigint | null {
  return data.length >= 16 ? readU64LE(data, 8) : null;
}

/** Parse a non-negative integer amount; anything else (decimals, "", NaN) is null. */
function toBigIntOrNull(
  value: string | number | bigint | undefined
): bigint | null {
  if (value === undefined || value === null) return null;
  if (typeof value === "bigint") return value >= BigInt(0) ? value : null;
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  }
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) return null;
  return BigInt(value);
}

// ---------------------------------------------------------------------------
// Main decode entry point (enterprise bundles)
// ---------------------------------------------------------------------------

/**
 * Decode a serialized (unsigned or partially signed) legacy Solana
 * transaction produced by the SSP relay vault-bundle builder and report
 * exactly what signing it authorizes.
 *
 * Outer instructions are classified against a strict allowlist
 * (nonceAdvance, ATA-program create funded by the fee payer, the four
 * multisig instructions and — only with `opts.allowComputeBudget` — capped
 * ComputeBudget); anything else lands in `unknownOuterPrograms` — a partial
 * signature authorizes EVERY outer instruction, so unknown outer programs are
 * the leaf-key-drain guard.
 *
 * When a `create_transaction` instruction is present, its inner
 * TransactionMessage is parsed and every inner instruction classified
 * (SystemProgram transfer, SPL TransferChecked, optional Memo); unclassifiable
 * inner instructions — including legacy SPL Transfer (tag 3) — are counted in
 * `unknownInnerInstructionCount` (fail-closed: callers must treat non-zero as
 * a mismatch).
 *
 * NEVER throws — all failures return `{ kind: "undecodable", error }`, which
 * callers MUST treat as a hard block.
 */
export function decodeVaultSolanaTransaction(
  serializedTxBase64: string,
  programId: PublicKey,
  opts?: DecodeVaultSolanaOptions
): DecodedVaultSolanaTx {
  try {
    const bundle = parseBundle(serializedTxBase64, programId);
    const paymaster = bundle.feePayer;

    // Re-create the outer allowlist verdict in instruction order.
    const flagged: Array<{ index: number; programId: string }> = [
      ...bundle.foreign,
    ];
    for (const ata of bundle.ataCreates) {
      // createAssociatedTokenAccount(Idempotent). A partial member signature
      // authorizes EVERY outer ix, so the rent FUNDER (keys[0]) must be the
      // fee payer / paymaster — otherwise a member leaf could be named as
      // funder and drained of its own lamports. Flag any other funder.
      if (paymaster && ata.funder && ata.funder !== paymaster) {
        flagged.push({
          index: ata.index,
          programId: ATA_PROGRAM_ID.toBase58(),
        });
      }
    }
    const cbCaps = opts?.allowComputeBudget;
    const seenCbTags = new Set<number>();
    for (const cb of bundle.computeBudget) {
      let ok = false;
      if (cbCaps && cb.value !== null && !seenCbTags.has(cb.tag)) {
        if (cb.tag === COMPUTE_BUDGET_TAG_SET_UNIT_LIMIT) {
          ok =
            cbCaps.maxUnitLimit === undefined ||
            cb.value <= BigInt(cbCaps.maxUnitLimit);
        } else if (cb.tag === COMPUTE_BUDGET_TAG_SET_UNIT_PRICE) {
          const cap = toBigIntOrNull(cbCaps.maxUnitPriceMicroLamports);
          ok =
            cbCaps.maxUnitPriceMicroLamports === undefined ||
            (cap !== null && cb.value <= cap);
        }
      }
      seenCbTags.add(cb.tag);
      if (!ok) {
        flagged.push({
          index: cb.index,
          programId: COMPUTE_BUDGET_PROGRAM_ID.toBase58(),
        });
      }
    }
    flagged.sort((a, b) => a.index - b.index);
    const unknownOuterPrograms = flagged.map((f) => f.programId);

    if (bundle.creates.length > 1) {
      throw new Error("multiple create_transaction instructions");
    }

    // Approve ix accounts: { multisig, transaction, member } (IDL order).
    // keys[1] = the proposal PDA the approval targets; keys[2] = the approving
    // member. Capture both — the target binds the signature to a specific
    // proposal (checked in compareDecodedToExpected).
    const approvers: string[] = [];
    const approveTargets: string[] = [];
    const approveMultisigs: string[] = [];
    for (const a of bundle.approves) {
      if (a.keys.length < 3) {
        throw new Error("approve_transaction instruction has too few accounts");
      }
      approveMultisigs.push(a.keys[0].toBase58());
      approveTargets.push(a.keys[1].toBase58());
      approvers.push(a.keys[2].toBase58());
    }
    // execute_transaction accounts: { multisig, transaction, executor }.
    // Capture its target proposal PDA (keys[1]) so the comparison can bind it
    // to the created / expected proposal (a swapped execute would otherwise
    // run a DIFFERENT proposal than the one shown).
    const executeTargets: string[] = bundle.executes
      .filter((e) => e.keys.length >= 2)
      .map((e) => e.keys[1].toBase58());

    if (bundle.creates.length === 1) {
      const createIx = bundle.creates[0];
      // Create ix accounts: { multisig, transaction, creator, payer,
      // systemProgram } (IDL order).
      if (createIx.keys.length < 3) {
        throw new Error("create_transaction instruction has too few accounts");
      }
      const inner = createIx.inner;
      if (inner.accountKeys.length === 0) {
        throw new Error("create_transaction inner message has no account keys");
      }
      const classified = classifyInnerMessage(
        inner,
        paymaster,
        opts?.allowMemo === true
      );

      // Optional ATA -> owner resolution for SPL recipients.
      if (opts?.expectedRecipientOwner && opts?.expectedMint) {
        resolveAtaOwner(
          classified.recipients,
          opts.expectedRecipientOwner,
          opts.expectedMint
        );
      }

      return {
        kind: "create",
        vaultIndex: inner.vaultIndex,
        multisigPda: createIx.keys[0].toBase58(),
        transactionPda: createIx.keys[1].toBase58(),
        creator: createIx.keys[2].toBase58(),
        sender: inner.accountKeys[0].toBase58(),
        recipients: classified.recipients,
        feeLamports: classified.feeLamports.toString(),
        feePayer: paymaster ?? null,
        approvers,
        approveTargets,
        executeTargets,
        unknownInnerInstructionCount: classified.unknownInnerInstructionCount,
        unknownOuterPrograms,
        memos: classified.memos,
      };
    }

    if (bundle.approves.length > 0) {
      const first = bundle.approves[0];
      const index = readTransactionIndexArg(first.data);
      return {
        kind: "approve",
        multisigPda: first.keys[0].toBase58(),
        transactionPda: first.keys[1].toBase58(),
        approvers,
        approveTargets,
        approveMultisigs,
        transactionIndex: index === null ? null : index.toString(),
        unknownOuterPrograms,
      };
    }

    throw new Error(
      "no create_transaction or approve_transaction instruction found"
    );
  } catch (error) {
    return {
      kind: "undecodable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// Fund-flow comparison (shared by bundle and on-chain proposal compare)
// ---------------------------------------------------------------------------

/** What the device is being asked to approve (relay/requester supplied). */
export interface ExpectedSolanaVaultPayload {
  recipients: Array<{ address: string; amount: string }>;
  /**
   * The token mint being sent. When set, EVERY decoded recipient must be an
   * SPL TransferChecked of exactly this mint; when unset, every decoded
   * recipient must be a native SOL transfer (an SPL transfer in a payload
   * presented as native is a mismatch).
   */
  tokenMint?: string;
  /**
   * When set, every SPL recipient's on-the-wire decimals must equal it. The
   * DISPLAY must still use the decoded decimals (or the device's own token
   * list), never a relay-supplied value.
   */
  tokenDecimals?: number;
  /**
   * Max lamports the vault may reimburse to the fee payer, summed over all
   * fee transfers. DEFAULT 0 — any vault→fee-payer outflow rejects unless the
   * caller sets this to the agreed network-fee/rent reimbursement. Never set
   * it open-ended: this bound is what stops the fee bucket hiding a drain.
   */
  maxFeeLamports?: string | number | bigint;
  /** If set, any fee reimbursement must be paid to this exact address. */
  expectedFeePayer?: string;
  /**
   * The proposal PDA the approver is being shown. When set, the created
   * proposal (kind:"create") or approve target (kind:"approve") must equal
   * it, binding the signature to the displayed proposal.
   */
  expectedTransactionPda?: string;
  /**
   * The multisig PDA of the vault the device expects to sign for, derived
   * LOCALLY (deriveMultisigAddress(members, threshold, programId)) — never
   * taken from the relay. When set, the decoded multisig must equal it
   * (SOL-7: stops the relay substituting another vault the signer is also a
   * member of). Callers SHOULD always set it once they can derive it.
   */
  expectedMultisigPda?: string;
  /** When set, the proposal's vault_index must equal it. */
  expectedVaultIndex?: number;
  /** When set, the debited vault PDA (inner account_keys[0]) must equal it. */
  expectedVaultPda?: string;
}

interface FundFlowView {
  recipients: DecodedSolanaVaultRecipient[];
  feeLamports: string;
  feePayer: string | null;
  unknownInnerInstructionCount: number;
}

/** Does `expectedAddress` name this decoded recipient (owner, raw dest, or owner of the ATA)? */
function recipientMatchesAddress(
  r: DecodedSolanaVaultRecipient,
  expectedAddress: string
): boolean {
  if (r.address === expectedAddress || r.ata === expectedAddress) return true;
  if (r.asset !== "spl" || !r.ata || !r.mint || !r.tokenProgram) return false;
  try {
    return (
      deriveAssociatedTokenAddress(
        new PublicKey(expectedAddress),
        new PublicKey(r.mint),
        new PublicKey(r.tokenProgram)
      ).toBase58() === r.ata
    );
  } catch {
    return false;
  }
}

type FundFlowExpectation = Pick<
  ExpectedSolanaVaultPayload,
  | "recipients"
  | "tokenMint"
  | "tokenDecimals"
  | "maxFeeLamports"
  | "expectedFeePayer"
>;

function compareFundFlows(
  view: FundFlowView,
  expected: FundFlowExpectation,
  mismatches: string[]
): void {
  if (view.unknownInnerInstructionCount > 0) {
    mismatches.push(
      `${view.unknownInnerInstructionCount} unrecognized inner instruction(s) in the transaction message`
    );
  }

  // Bound the vault→fee-payer reimbursement. Any outflow beyond the explicit
  // cap (default 0) is a mismatch — this is what stops the fee bucket smuggling
  // an unbounded vault drain past the recipient check.
  const decodedFee = toBigIntOrNull(view.feeLamports) ?? BigInt(0);
  const maxFee =
    expected.maxFeeLamports === undefined
      ? BigInt(0)
      : toBigIntOrNull(
          typeof expected.maxFeeLamports === "number"
            ? expected.maxFeeLamports
            : String(expected.maxFeeLamports)
        );
  if (maxFee === null) {
    mismatches.push(
      `invalid maxFeeLamports: ${String(expected.maxFeeLamports)}`
    );
  } else if (decodedFee > maxFee) {
    mismatches.push(
      `vault->fee-payer outflow of ${decodedFee.toString()} lamports exceeds the allowed maximum of ${maxFee.toString()}`
    );
  }
  if (
    decodedFee > BigInt(0) &&
    expected.expectedFeePayer &&
    view.feePayer !== expected.expectedFeePayer
  ) {
    mismatches.push(
      `fee paid to ${view.feePayer ?? "unknown"}, expected fee payer ${
        expected.expectedFeePayer
      }`
    );
  }

  // Multiset match: every expected recipient must be found exactly once.
  const pool = view.recipients.map((r) => ({ recipient: r, used: false }));
  for (const exp of expected.recipients) {
    const expAmount = toBigIntOrNull(exp.amount);
    const index = pool.findIndex((entry) => {
      if (entry.used) return false;
      const r = entry.recipient;
      if (!recipientMatchesAddress(r, exp.address)) return false;
      if (expAmount === null) return false;
      const decodedAmount = toBigIntOrNull(r.amount);
      return decodedAmount !== null && decodedAmount === expAmount;
    });
    if (index < 0) {
      mismatches.push(
        `expected recipient ${exp.address} with amount ${exp.amount} not found in decoded transaction`
      );
    } else {
      pool[index].used = true;
    }
  }
  for (const entry of pool) {
    if (!entry.used) {
      mismatches.push(
        `decoded recipient ${entry.recipient.address} with amount ${entry.recipient.amount} is not present in the expected payload`
      );
    }
  }

  // Asset / mint / decimals binding (SOL-5 / CHN-3 / H-14).
  for (const r of view.recipients) {
    if (r.asset === "spl") {
      if (!r.mint) {
        mismatches.push(
          `SPL transfer to ${r.address} carries no mint on the wire (legacy Transfer) and cannot be verified`
        );
        continue;
      }
      if (!expected.tokenMint) {
        mismatches.push(
          `decoded SPL token transfer of mint ${r.mint} but the expected payload is a native SOL transfer`
        );
      } else if (r.mint !== expected.tokenMint) {
        mismatches.push(
          `decoded token mint ${r.mint} does not match expected mint ${expected.tokenMint}`
        );
      }
      if (
        expected.tokenDecimals !== undefined &&
        r.decimals !== expected.tokenDecimals
      ) {
        mismatches.push(
          `decoded token decimals ${String(
            r.decimals
          )} do not match expected decimals ${expected.tokenDecimals}`
        );
      }
    } else if (expected.tokenMint) {
      mismatches.push(
        `decoded native SOL transfer to ${r.address} but the expected payload is a token transfer of mint ${expected.tokenMint}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Byte-decode vs relay-payload comparison
// ---------------------------------------------------------------------------

/**
 * Compare a decoded vault transaction against the relay-supplied display
 * payload. `ok: false` means the bytes contradict the payload (or cannot be
 * fully verified) — an active-attack indicator that callers MUST HARD-BLOCK on.
 *
 * The gate is FAIL-CLOSED: every value that moves funds must be positively
 * accounted for by `expected`, or the comparison rejects.
 *
 * - kind "create":
 *     • every expected recipient must appear in the decode with an exact
 *       base-unit amount match (matching on owner, raw destination, or the
 *       owner whose ATA the destination is); every decoded recipient must be
 *       expected (extras = mismatch);
 *     • asset binding: with `tokenMint` every recipient must be an SPL
 *       TransferChecked of that mint (and `tokenDecimals` when set); without
 *       it every recipient must be native SOL;
 *     • the vault→fee-payer reimbursement (`feeLamports`) must be <=
 *       `expected.maxFeeLamports` (DEFAULT 0) and, if `expected.expectedFeePayer`
 *       is set, be paid to that address;
 *     • every bundled approve_transaction / execute_transaction must target the
 *       created proposal (and `expected.expectedTransactionPda` when set);
 *     • the multisig / vault index / vault PDA must equal the expected ones
 *       when set (SOL-7);
 *     • any unknown outer program or unknown inner instruction = mismatch.
 * - kind "approve": an approve-only bundle carries NO proposal message, so its
 *   fund movement is not verifiable from these bytes. Rejected unless the caller
 *   sets `expected.approveOnlyVerifiedOnChain` (asserting it fetched and
 *   verified the on-chain VaultTransaction at `expected.expectedTransactionPda`
 *   — see {@link verifyApproveOnlyTransaction}, which does exactly that).
 * - kind "undecodable": never ok.
 */
export function compareDecodedToExpected(
  decoded: DecodedVaultSolanaTx,
  expected: ExpectedSolanaVaultPayload & {
    /**
     * Approve-only bundles have no message to verify. Set this ONLY after
     * independently fetching the on-chain VaultTransaction at
     * expectedTransactionPda and verifying its stored recipients/amounts
     * (compareProposalToExpected); expectedTransactionPda is required
     * alongside it.
     */
    approveOnlyVerifiedOnChain?: boolean;
  }
): { ok: boolean; mismatches: string[] } {
  if (decoded.kind === "undecodable") {
    return {
      ok: false,
      mismatches: [`transaction bytes are undecodable: ${decoded.error}`],
    };
  }

  const mismatches: string[] = [];

  if (decoded.unknownOuterPrograms.length > 0) {
    mismatches.push(
      `unknown outer program instruction(s): ${decoded.unknownOuterPrograms.join(
        ", "
      )}`
    );
  }

  if (
    expected.expectedMultisigPda &&
    decoded.multisigPda !== expected.expectedMultisigPda
  ) {
    mismatches.push(
      `multisig ${decoded.multisigPda} does not match the expected vault multisig ${expected.expectedMultisigPda}`
    );
  }

  if (decoded.kind === "approve") {
    // Every approve in the bundle must target the same proposal of the same
    // multisig (a second approve could otherwise harvest a signature for a
    // different proposal than the one verified).
    for (const t of decoded.approveTargets) {
      if (t !== decoded.transactionPda) {
        mismatches.push(
          `approve_transaction targets ${t}, not the bundle's proposal ${decoded.transactionPda}`
        );
      }
      if (
        expected.expectedTransactionPda &&
        t !== expected.expectedTransactionPda
      ) {
        mismatches.push(
          `approve_transaction targets ${t}, expected proposal ${expected.expectedTransactionPda}`
        );
      }
    }
    for (const m of decoded.approveMultisigs ?? []) {
      if (m !== decoded.multisigPda) {
        mismatches.push(
          `approve_transaction names multisig ${m}, not the bundle's multisig ${decoded.multisigPda}`
        );
      }
    }
    if (
      expected.expectedTransactionPda &&
      decoded.transactionPda !== expected.expectedTransactionPda
    ) {
      mismatches.push(
        `approve targets proposal ${decoded.transactionPda}, expected ${expected.expectedTransactionPda}`
      );
    }
    if (!expected.approveOnlyVerifiedOnChain) {
      mismatches.push(
        "approve-only transaction: the proposal message is not present in these bytes. Fetch the on-chain VaultTransaction at the target PDA, verify its recipients/amounts, then set approveOnlyVerifiedOnChain (with expectedTransactionPda) to approve."
      );
    } else if (!expected.expectedTransactionPda) {
      mismatches.push(
        "approveOnlyVerifiedOnChain set without expectedTransactionPda: cannot confirm which proposal was verified"
      );
    }
    return { ok: mismatches.length === 0, mismatches };
  }

  // ---- kind: "create" ----

  if (
    expected.expectedVaultIndex !== undefined &&
    decoded.vaultIndex !== expected.expectedVaultIndex
  ) {
    mismatches.push(
      `proposal vault index ${decoded.vaultIndex} does not match expected ${expected.expectedVaultIndex}`
    );
  }
  if (
    expected.expectedVaultPda &&
    decoded.sender !== expected.expectedVaultPda
  ) {
    mismatches.push(
      `debited vault ${decoded.sender} does not match the expected vault ${expected.expectedVaultPda}`
    );
  }

  // Bind every bundled approve/execute to the created proposal — a relay that
  // swaps an approve/execute onto a DIFFERENT (e.g. abandoned) proposal than
  // the one shown would otherwise harvest the deciding signature on it.
  for (const t of decoded.approveTargets) {
    if (t !== decoded.transactionPda) {
      mismatches.push(
        `approve_transaction targets ${t}, not the created proposal ${decoded.transactionPda}`
      );
    }
  }
  for (const t of decoded.executeTargets) {
    if (t !== decoded.transactionPda) {
      mismatches.push(
        `execute_transaction targets ${t}, not the created proposal ${decoded.transactionPda}`
      );
    }
  }
  if (
    expected.expectedTransactionPda &&
    decoded.transactionPda !== expected.expectedTransactionPda
  ) {
    mismatches.push(
      `created proposal ${decoded.transactionPda} does not match expected ${expected.expectedTransactionPda}`
    );
  }

  compareFundFlows(decoded, expected, mismatches);

  return { ok: mismatches.length === 0, mismatches };
}

// ---------------------------------------------------------------------------
// On-chain proposal (VaultTransaction) decode — approve-only path (H-13)
// ---------------------------------------------------------------------------

/** Minimal account shape (structurally compatible with web3.js AccountInfo). */
export interface SolanaAccountInfoLike {
  owner: PublicKey;
  data: Uint8Array;
}

/** Minimal connection shape (structurally compatible with web3.js Connection). */
export interface SolanaConnectionLike {
  getAccountInfo(
    publicKey: PublicKey,
    commitment?: "processed" | "confirmed" | "finalized"
  ): Promise<SolanaAccountInfoLike | null>;
}

export type DecodedOnChainProposal =
  | {
      kind: "proposal";
      /** The account the proposal was read from. */
      transactionPda: string;
      multisigPda: string;
      transactionIndex: string;
      creator: string;
      /** Rent funder (paymaster). */
      payer: string;
      vaultIndex: number;
      /** Vault PDA derived from (multisig, vaultIndex, programId). */
      vaultPda: string;
      executed: boolean;
      approvals: string[];
      /** Stored message account_keys[0] — must equal vaultPda. */
      sender: string;
      recipients: DecodedSolanaVaultRecipient[];
      /** Inner vault→feePayer reimbursement total (lamports). */
      feeLamports: string;
      /** Address reimbursements were bucketed against (opts.feePayer ?? payer). */
      feePayer: string | null;
      unknownInnerInstructionCount: number;
      memos: string[];
    }
  | { kind: "undecodable"; error: string };

export interface DecodeProposalOptions {
  /**
   * Address whose inner native transfers count as the fee reimbursement.
   * Defaults to the proposal's stored rent `payer` (the paymaster).
   */
  feePayer?: string;
  /** Accept inner SPL Memo v2 (see DecodeVaultSolanaOptions.allowMemo). */
  allowMemo?: boolean;
  expectedRecipientOwner?: string;
  expectedMint?: string;
}

/**
 * Decode raw `VaultTransaction` account data (pure, offline, never throws).
 *
 * Verifies the Anchor account discriminator and that `transactionPda` is the
 * canonical PDA of the stored (multisig, transaction_index) under `programId`
 * — so bytes taken from any other account (or a look-alike) are refused. The
 * caller is responsible for checking the account OWNER is `programId`
 * (fetchAndDecodeProposal does).
 */
export function decodeVaultTransactionAccount(
  data: Uint8Array,
  transactionPda: PublicKey,
  programId: PublicKey,
  opts?: DecodeProposalOptions
): DecodedOnChainProposal {
  try {
    const buf = Buffer.from(data);
    const reader = new ByteReader(buf);
    const disc = Uint8Array.from(reader.bytes(8));
    if (!bytesEqual(disc, VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR)) {
      throw new Error(
        "account is not a VaultTransaction (discriminator mismatch)"
      );
    }
    const multisig = reader.pubkey();
    const transactionIndex = reader.u64();
    const creator = reader.pubkey();
    const payer = reader.pubkey();
    reader.u8(); // bump
    const vaultIndex = reader.u8();
    reader.u8(); // vault_bump
    const executed = reader.bool();
    const approvalCount = reader.u32();
    const approvals: string[] = [];
    for (let i = 0; i < approvalCount; i++) {
      approvals.push(reader.pubkey().toBase58());
    }
    // Trailing bytes (unused approval capacity) are ignored, as Anchor does.
    const inner = parseTransactionMessage(reader, vaultIndex);

    const canonicalPda = deriveTransactionPda(
      multisig,
      transactionIndex,
      programId
    );
    if (!canonicalPda.equals(transactionPda)) {
      throw new Error(
        `account ${transactionPda.toBase58()} is not the canonical proposal PDA for multisig ${multisig.toBase58()} index ${transactionIndex.toString()}`
      );
    }

    const feePayer = opts?.feePayer ?? payer.toBase58();
    const classified = classifyInnerMessage(
      inner,
      feePayer,
      opts?.allowMemo === true
    );
    if (opts?.expectedRecipientOwner && opts?.expectedMint) {
      resolveAtaOwner(
        classified.recipients,
        opts.expectedRecipientOwner,
        opts.expectedMint
      );
    }

    return {
      kind: "proposal",
      transactionPda: transactionPda.toBase58(),
      multisigPda: multisig.toBase58(),
      transactionIndex: transactionIndex.toString(),
      creator: creator.toBase58(),
      payer: payer.toBase58(),
      vaultIndex,
      vaultPda: deriveVaultPda(multisig, vaultIndex, programId).toBase58(),
      executed,
      approvals,
      sender: inner.accountKeys[0].toBase58(),
      recipients: classified.recipients,
      feeLamports: classified.feeLamports.toString(),
      feePayer,
      unknownInnerInstructionCount: classified.unknownInnerInstructionCount,
      memos: classified.memos,
    };
  } catch (error) {
    return {
      kind: "undecodable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Fetch the on-chain `VaultTransaction` at `transactionPda` and decode its
 * stored message (never throws). Refuses a missing account, an account not
 * owned by `programId`, a non-VaultTransaction account and a non-canonical
 * PDA. Use the device's OWN RPC endpoint, never one supplied by the relay.
 */
export async function fetchAndDecodeProposal(
  connection: SolanaConnectionLike,
  transactionPda: PublicKey | string,
  programId: PublicKey,
  opts?: DecodeProposalOptions & {
    commitment?: "processed" | "confirmed" | "finalized";
  }
): Promise<DecodedOnChainProposal> {
  try {
    const pda =
      typeof transactionPda === "string"
        ? new PublicKey(transactionPda)
        : transactionPda;
    const info = await connection.getAccountInfo(
      pda,
      opts?.commitment ?? "confirmed"
    );
    if (!info) {
      throw new Error(`proposal account ${pda.toBase58()} not found on-chain`);
    }
    if (!info.owner.equals(programId)) {
      throw new Error(
        `proposal account ${pda.toBase58()} is owned by ${info.owner.toBase58()}, not the multisig program ${programId.toBase58()}`
      );
    }
    return decodeVaultTransactionAccount(info.data, pda, programId, opts);
  } catch (error) {
    return {
      kind: "undecodable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Compare a decoded on-chain proposal against the payload the device is
 * displaying. Fail-closed: `ok` only when the proposal is open (not executed),
 * belongs to the expected multisig, debits that multisig's vault, and its
 * stored fund flows match `expected` exactly (same rules as
 * compareDecodedToExpected's create path).
 *
 * `expectedMultisigPda` is REQUIRED: pass the locally derived multisig PDA, or
 * `null` to explicitly skip the vault binding (only while the vault descriptor
 * is not pinned on the device — this leaves SOL-7 open).
 */
export function compareProposalToExpected(
  proposal: DecodedOnChainProposal,
  expected: Omit<ExpectedSolanaVaultPayload, "expectedMultisigPda"> & {
    expectedMultisigPda: string | null;
  }
): { ok: boolean; mismatches: string[] } {
  if (proposal.kind === "undecodable") {
    return {
      ok: false,
      mismatches: [`on-chain proposal is undecodable: ${proposal.error}`],
    };
  }
  const mismatches: string[] = [];
  if (proposal.executed) {
    mismatches.push(
      `proposal ${proposal.transactionPda} has already been executed`
    );
  }
  if (expected.expectedMultisigPda === undefined) {
    mismatches.push(
      "expectedMultisigPda must be provided (or explicitly null)"
    );
  } else if (
    expected.expectedMultisigPda !== null &&
    proposal.multisigPda !== expected.expectedMultisigPda
  ) {
    mismatches.push(
      `proposal belongs to multisig ${proposal.multisigPda}, expected ${expected.expectedMultisigPda}`
    );
  }
  if (proposal.sender !== proposal.vaultPda) {
    mismatches.push(
      `proposal debits ${proposal.sender}, not its vault PDA ${proposal.vaultPda}`
    );
  }
  if (
    expected.expectedVaultIndex !== undefined &&
    proposal.vaultIndex !== expected.expectedVaultIndex
  ) {
    mismatches.push(
      `proposal vault index ${proposal.vaultIndex} does not match expected ${expected.expectedVaultIndex}`
    );
  }
  if (
    expected.expectedVaultPda &&
    proposal.vaultPda !== expected.expectedVaultPda
  ) {
    mismatches.push(
      `proposal vault ${proposal.vaultPda} does not match the expected vault ${expected.expectedVaultPda}`
    );
  }
  if (
    expected.expectedTransactionPda &&
    proposal.transactionPda !== expected.expectedTransactionPda
  ) {
    mismatches.push(
      `proposal ${proposal.transactionPda} does not match expected ${expected.expectedTransactionPda}`
    );
  }
  compareFundFlows(proposal, expected, mismatches);
  return { ok: mismatches.length === 0, mismatches };
}

/**
 * The complete approve-only (split-flow) gate (H-13 / SOL-3 / CHN-4):
 *  1. decode the approve-only bundle (outer allowlist, single proposal target);
 *  2. fetch the on-chain VaultTransaction at that target via the device's RPC;
 *  3. decode its stored message and compare it to the displayed payload;
 *  4. only then accept the bundle (compareDecodedToExpected with
 *     approveOnlyVerifiedOnChain + the verified target).
 *
 * Never throws. `ok: false` MUST block signing. On success, display the
 * values from `proposal` (decoded from chain), not the relay payload.
 */
export async function verifyApproveOnlyTransaction(params: {
  connection: SolanaConnectionLike;
  serializedTxBase64: string;
  programId: PublicKey;
  expected: Omit<ExpectedSolanaVaultPayload, "expectedMultisigPda"> & {
    expectedMultisigPda: string | null;
  };
  /** The device's own member pubkey: it must be the approver in the bundle. */
  expectedApprover?: string;
  decodeOptions?: DecodeVaultSolanaOptions;
  proposalOptions?: DecodeProposalOptions & {
    commitment?: "processed" | "confirmed" | "finalized";
  };
}): Promise<{
  ok: boolean;
  mismatches: string[];
  decoded: DecodedVaultSolanaTx;
  proposal: DecodedOnChainProposal | null;
}> {
  const decoded = decodeVaultSolanaTransaction(
    params.serializedTxBase64,
    params.programId,
    params.decodeOptions
  );
  if (decoded.kind !== "approve") {
    return {
      ok: false,
      mismatches: [
        decoded.kind === "undecodable"
          ? `transaction bytes are undecodable: ${decoded.error}`
          : `expected an approve-only transaction, got kind '${decoded.kind}'`,
      ],
      decoded,
      proposal: null,
    };
  }
  const mismatches: string[] = [];
  if (params.expectedApprover) {
    if (!decoded.approvers.includes(params.expectedApprover)) {
      mismatches.push(
        `the bundle does not approve as ${
          params.expectedApprover
        } (approvers: ${decoded.approvers.join(", ")})`
      );
    }
  }
  const proposal = await fetchAndDecodeProposal(
    params.connection,
    decoded.transactionPda,
    params.programId,
    {
      ...(params.expected.expectedFeePayer
        ? { feePayer: params.expected.expectedFeePayer }
        : {}),
      ...(params.proposalOptions ?? {}),
    }
  );
  const proposalCmp = compareProposalToExpected(proposal, {
    ...params.expected,
    expectedTransactionPda:
      params.expected.expectedTransactionPda ?? decoded.transactionPda,
  });
  mismatches.push(...proposalCmp.mismatches);
  if (proposal.kind === "proposal") {
    if (decoded.multisigPda !== proposal.multisigPda) {
      mismatches.push(
        `approve names multisig ${decoded.multisigPda}, the proposal belongs to ${proposal.multisigPda}`
      );
    }
    if (
      decoded.transactionIndex !== undefined &&
      decoded.transactionIndex !== null &&
      decoded.transactionIndex !== proposal.transactionIndex
    ) {
      mismatches.push(
        `approve transaction_index ${decoded.transactionIndex} does not match the proposal's ${proposal.transactionIndex}`
      );
    }
  }
  const bundleCmp = compareDecodedToExpected(decoded, {
    recipients: [],
    ...(params.expected.expectedMultisigPda
      ? { expectedMultisigPda: params.expected.expectedMultisigPda }
      : {}),
    expectedTransactionPda: decoded.transactionPda,
    approveOnlyVerifiedOnChain: proposalCmp.ok,
  });
  for (const m of bundleCmp.mismatches) {
    if (!mismatches.includes(m)) mismatches.push(m);
  }
  return { ok: mismatches.length === 0, mismatches, decoded, proposal };
}

// ---------------------------------------------------------------------------
// Consumer 2-of-2 send bundle gate (C-3 / SOL-1 / CHN-1)
// ---------------------------------------------------------------------------

export interface ConsumerSolanaBundleParams {
  programId: PublicKey;
  /**
   * The vault's multisig PDA, derived LOCALLY from the device's stored member
   * pubkeys: deriveMultisigAddress(members, threshold, programId). Never take
   * it from the request.
   */
  multisigPda: string;
  /** The vault members (base58), e.g. [walletLeaf, keyLeaf]. */
  members: string[];
  /** The signing device's own member pubkey (base58). */
  signer: string;
  /** Vault index under the multisig (consumer: 0). */
  vaultIndex?: number;
  expected: {
    /** Recipient OWNER for SPL (the decoder checks the ATA), address for SOL. */
    recipient: string;
    amount: string;
    tokenMint?: string;
    tokenDecimals?: number;
  };
  /** Cap on the vault→fee-payer reimbursement (lamports). Required. */
  maxFeeLamports: string | number | bigint;
  /** The paymaster expected as fee payer (recommended). */
  expectedFeePayer?: string;
  /** Caps on outer ComputeBudget instructions (optional; paid by the fee payer). */
  maxComputeUnitLimit?: number;
  maxComputeUnitPriceMicroLamports?: string | number | bigint;
}

export interface ConsumerSolanaBundleDecoded {
  multisigPda: string;
  vaultPda: string;
  transactionPda: string;
  feePayer: string | null;
  /** Owner-resolved recipients decoded from the signed bytes. */
  recipients: DecodedSolanaVaultRecipient[];
  feeLamports: string;
  memos: string[];
  computeUnitLimit: string | null;
  computeUnitPriceMicroLamports: string | null;
}

/**
 * Fail-closed verification of a consumer (wallet ↔ key 2-of-2) Solana send
 * bundle, as built by ssp-wallet `constructAndSignSOLTransaction`:
 *
 *   [nonceAdvance] [ComputeBudget limit/price] [ATA createIdempotent]
 *   create  approve(wallet)  approve(key)  execute  close
 *
 * Every rule must hold or `ok` is false (refuse to sign):
 *  - the fee payer exists and is NOT a vault member (a member must never pay
 *    the — possibly priority — fee); equals expectedFeePayer when set;
 *  - outer allowlist only: nonceAdvance (once, first), ComputeBudget
 *    SetComputeUnitLimit/SetComputeUnitPrice (each at most once, capped),
 *    at most one ATA create funded by the fee payer whose ATA is the derived
 *    ATA of the expected recipient for the expected mint, exactly ONE
 *    create_transaction, approvals by distinct members, at most one execute
 *    and one close; every multisig instruction names `multisigPda` and the
 *    created proposal;
 *  - the proposal's vault index equals `vaultIndex` (default 0) and debits the
 *    vault PDA derived from `multisigPda`;
 *  - the inner message moves funds ONLY to the expected recipient (exact
 *    amount; SPL via TransferChecked of the expected mint/decimals into the
 *    recipient's derived ATA), plus a fee reimbursement to the fee payer
 *    capped by maxFeeLamports; optional Memo v2; nothing else.
 *
 * Never throws.
 */
export function verifyConsumerSolanaBundle(
  serializedTxBase64: string,
  params: ConsumerSolanaBundleParams
): {
  ok: boolean;
  mismatches: string[];
  decoded: ConsumerSolanaBundleDecoded | null;
} {
  const mismatches: string[] = [];
  try {
    const { programId } = params;
    const vaultIndex = params.vaultIndex ?? 0;
    const multisig = new PublicKey(params.multisigPda);
    const multisigPda = multisig.toBase58();
    const members = params.members.map((m) => new PublicKey(m).toBase58());
    const signer = new PublicKey(params.signer).toBase58();
    if (!members.includes(signer)) {
      throw new Error(`signer ${signer} is not a member of the vault`);
    }
    if (new Set(members).size !== members.length) {
      throw new Error("duplicate vault members");
    }
    const vaultPda = deriveVaultPda(multisig, vaultIndex, programId).toBase58();
    const bundle = parseBundle(serializedTxBase64, programId);
    const feePayer = bundle.feePayer ?? null;

    // ---- fee payer ----
    if (!feePayer) {
      mismatches.push("transaction has no fee payer");
    } else {
      if (members.includes(feePayer)) {
        mismatches.push(`fee payer ${feePayer} is a vault member`);
      }
      if (params.expectedFeePayer && feePayer !== params.expectedFeePayer) {
        mismatches.push(
          `fee payer ${feePayer} does not match the expected paymaster ${params.expectedFeePayer}`
        );
      }
    }

    // ---- outer allowlist ----
    for (const f of bundle.foreign) {
      mismatches.push(
        `unknown outer instruction #${f.index} (program ${f.programId})`
      );
    }
    if (bundle.nonceAdvanceIndexes.length > 1) {
      mismatches.push("more than one nonceAdvance instruction");
    }
    for (const i of bundle.nonceAdvanceIndexes) {
      if (i !== 0)
        mismatches.push(`nonceAdvance at position ${i}, must be first`);
    }
    let computeUnitLimit: bigint | null = null;
    let computeUnitPrice: bigint | null = null;
    for (const cb of bundle.computeBudget) {
      if (cb.value === null) {
        mismatches.push(`unsupported ComputeBudget instruction #${cb.index}`);
      } else if (cb.tag === COMPUTE_BUDGET_TAG_SET_UNIT_LIMIT) {
        if (computeUnitLimit !== null)
          mismatches.push("duplicate SetComputeUnitLimit");
        computeUnitLimit = cb.value;
        if (
          params.maxComputeUnitLimit !== undefined &&
          cb.value > BigInt(params.maxComputeUnitLimit)
        ) {
          mismatches.push(
            `compute unit limit ${cb.value.toString()} exceeds the cap ${
              params.maxComputeUnitLimit
            }`
          );
        }
      } else {
        if (computeUnitPrice !== null)
          mismatches.push("duplicate SetComputeUnitPrice");
        computeUnitPrice = cb.value;
        const cap = toBigIntOrNull(params.maxComputeUnitPriceMicroLamports);
        if (params.maxComputeUnitPriceMicroLamports !== undefined) {
          if (cap === null) {
            mismatches.push("invalid maxComputeUnitPriceMicroLamports");
          } else if (cb.value > cap) {
            mismatches.push(
              `compute unit price ${cb.value.toString()} exceeds the cap ${cap.toString()}`
            );
          }
        }
      }
    }

    // ---- multisig instructions ----
    if (bundle.creates.length !== 1) {
      throw new Error(
        `expected exactly one create_transaction instruction, found ${bundle.creates.length}`
      );
    }
    const create = bundle.creates[0];
    if (create.keys.length < 4) {
      throw new Error("create_transaction instruction has too few accounts");
    }
    const transactionPda = create.keys[1].toBase58();
    if (create.keys[0].toBase58() !== multisigPda) {
      mismatches.push(
        `create_transaction names multisig ${create.keys[0].toBase58()}, expected ${multisigPda}`
      );
    }
    if (!members.includes(create.keys[2].toBase58())) {
      mismatches.push(
        `proposal creator ${create.keys[2].toBase58()} is not a vault member`
      );
    }
    const seenApprovers = new Set<string>();
    for (const a of bundle.approves) {
      if (a.keys.length < 3) {
        throw new Error("approve_transaction instruction has too few accounts");
      }
      const approver = a.keys[2].toBase58();
      if (a.keys[0].toBase58() !== multisigPda) {
        mismatches.push(
          `approve_transaction names multisig ${a.keys[0].toBase58()}`
        );
      }
      if (a.keys[1].toBase58() !== transactionPda) {
        mismatches.push(
          `approve_transaction targets ${a.keys[1].toBase58()}, not the created proposal ${transactionPda}`
        );
      }
      if (!members.includes(approver)) {
        mismatches.push(`approver ${approver} is not a vault member`);
      }
      if (seenApprovers.has(approver)) {
        mismatches.push(`duplicate approval by ${approver}`);
      }
      seenApprovers.add(approver);
    }
    if (!seenApprovers.has(signer)) {
      mismatches.push(
        `the bundle contains no approval by the signer ${signer}`
      );
    }
    if (bundle.executes.length > 1)
      mismatches.push("more than one execute_transaction");
    if (bundle.closes.length > 1)
      mismatches.push("more than one close_transaction");
    for (const [label, list] of [
      ["execute_transaction", bundle.executes],
      ["close_transaction", bundle.closes],
    ] as const) {
      for (const ix of list) {
        if (ix.keys.length < 2) {
          mismatches.push(`${label} has too few accounts`);
          continue;
        }
        if (ix.keys[0].toBase58() !== multisigPda) {
          mismatches.push(`${label} names multisig ${ix.keys[0].toBase58()}`);
        }
        if (ix.keys[1].toBase58() !== transactionPda) {
          mismatches.push(
            `${label} targets ${ix.keys[1].toBase58()}, not the created proposal ${transactionPda}`
          );
        }
      }
    }

    // ---- inner message ----
    const inner = create.inner;
    if (inner.vaultIndex !== vaultIndex) {
      mismatches.push(
        `proposal vault index ${inner.vaultIndex}, expected ${vaultIndex}`
      );
    }
    if (inner.accountKeys.length === 0) {
      throw new Error("create_transaction inner message has no account keys");
    }
    if (inner.accountKeys[0].toBase58() !== vaultPda) {
      mismatches.push(
        `proposal debits ${inner.accountKeys[0].toBase58()}, not the vault ${vaultPda}`
      );
    }
    const classified = classifyInnerMessage(inner, feePayer ?? undefined, true);
    if (params.expected.tokenMint) {
      resolveAtaOwner(
        classified.recipients,
        params.expected.recipient,
        params.expected.tokenMint
      );
    }
    compareFundFlows(
      {
        recipients: classified.recipients,
        feeLamports: classified.feeLamports.toString(),
        feePayer,
        unknownInnerInstructionCount: classified.unknownInnerInstructionCount,
      },
      {
        recipients: [
          {
            address: params.expected.recipient,
            amount: params.expected.amount,
          },
        ],
        tokenMint: params.expected.tokenMint,
        tokenDecimals: params.expected.tokenDecimals,
        maxFeeLamports: params.maxFeeLamports,
        expectedFeePayer: params.expectedFeePayer,
      },
      mismatches
    );
    // SPL destination must be the recipient's ATA (not just any account
    // labelled with the recipient); native recipient must be the address.
    for (const r of classified.recipients) {
      if (r.asset === "spl" && r.ataVerified !== true) {
        mismatches.push(
          `token destination ${
            r.ata ?? r.address
          } is not the associated token account of ${params.expected.recipient}`
        );
      }
    }

    // ---- ATA creation (outer) ----
    if (bundle.ataCreates.length > 1) {
      mismatches.push(
        "more than one associated-token-account create instruction"
      );
    }
    for (const ata of bundle.ataCreates) {
      const destination = classified.recipients.find(
        (r) => r.asset === "spl" && r.ata === ata.ata
      );
      if (!ata.dataOk)
        mismatches.push("unsupported associated-token-account instruction");
      if (!feePayer || ata.funder !== feePayer) {
        mismatches.push(
          `ATA create funded by ${ata.funder ?? "unknown"}, not the fee payer`
        );
      }
      if (
        !destination ||
        !ata.owner ||
        !ata.mint ||
        ata.owner !== params.expected.recipient ||
        ata.mint !== params.expected.tokenMint ||
        !ata.tokenProgram ||
        destination.tokenProgram !== ata.tokenProgram
      ) {
        mismatches.push(
          "ATA create does not match the recipient's token account"
        );
      } else {
        try {
          const derived = deriveAssociatedTokenAddress(
            new PublicKey(ata.owner),
            new PublicKey(ata.mint),
            new PublicKey(ata.tokenProgram)
          ).toBase58();
          if (derived !== ata.ata) {
            mismatches.push(
              "ATA create address is not the derived associated token account"
            );
          }
        } catch {
          mismatches.push("ATA create accounts are invalid");
        }
      }
    }

    return {
      ok: mismatches.length === 0,
      mismatches,
      decoded: {
        multisigPda,
        vaultPda,
        transactionPda,
        feePayer,
        recipients: classified.recipients,
        feeLamports: classified.feeLamports.toString(),
        memos: classified.memos,
        computeUnitLimit:
          computeUnitLimit === null ? null : String(computeUnitLimit),
        computeUnitPriceMicroLamports:
          computeUnitPrice === null ? null : String(computeUnitPrice),
      },
    };
  } catch (error) {
    mismatches.push(
      `transaction bytes are undecodable: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
    return { ok: false, mismatches, decoded: null };
  }
}
