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
 * The decoder NEVER throws — any parse failure returns
 * `{ kind: "undecodable", error }` so callers can degrade to a
 * warn-but-allow state without wrapping in try/catch.
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
  /** Token mint (TransferChecked only — legacy Transfer carries no mint). */
  mint?: string;
  /** Token decimals (TransferChecked only). */
  decimals?: number;
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
    }
  | {
      kind: "approve";
      multisigPda: string;
      transactionPda: string;
      approvers: string[];
      /** Proposal PDA each `approve_transaction` targets (keys[1]). */
      approveTargets: string[];
      unknownOuterPrograms: string[];
    }
  | { kind: "undecodable"; error: string };

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
 * Parse `create_transaction` instruction data. Borsh layout verified against
 * sdk/src/idl/solana_multisig.json:
 *   [0..8)   discriminator
 *   [8]      vault_index: u8
 *   [9]      num_signers: u8
 *   [10]     num_writable_signers: u8
 *   [11]     num_writable_non_signers: u8
 *   u32-LE   account_keys length, then N x 32-byte pubkeys
 *   u32-LE   instruction count, then per instruction:
 *              u8 program_id_index,
 *              u32-LE account_indexes length + bytes,
 *              u32-LE data length + bytes
 *   u32-LE   address_table_lookups length (+ entries)
 */
function parseCreateTransactionData(data: Buffer): InnerMessage {
  const reader = new ByteReader(data);
  reader.bytes(8); // discriminator (already matched by caller)
  const vaultIndex = reader.u8();
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

  return { vaultIndex, accountKeys, instructions, addressTableLookupCount };
}

// ---------------------------------------------------------------------------
// Main decode entry point
// ---------------------------------------------------------------------------

const SYSTEM_IX_TAG_TRANSFER = 2;
const SYSTEM_IX_TAG_NONCE_ADVANCE = 4;
const SPL_IX_TAG_TRANSFER = 3;
const SPL_IX_TAG_TRANSFER_CHECKED = 12;

/**
 * Decode a serialized (unsigned or partially signed) legacy Solana
 * transaction produced by the SSP relay vault-bundle builder and report
 * exactly what signing it authorizes.
 *
 * Outer instructions are classified against a strict allowlist
 * (nonceAdvance, ATA-program create, and the four multisig instructions);
 * anything else lands in `unknownOuterPrograms` — a partial signature
 * authorizes EVERY outer instruction, so unknown outer programs are the
 * leaf-key-drain guard.
 *
 * When a `create_transaction` instruction is present, its inner
 * TransactionMessage is parsed and every inner instruction classified
 * (SystemProgram transfer, SPL Transfer / TransferChecked); unclassifiable
 * inner instructions are counted in `unknownInnerInstructionCount`
 * (fail-closed: callers must treat non-zero as a mismatch).
 *
 * NEVER throws — all failures return `{ kind: "undecodable", error }`.
 */
export function decodeVaultSolanaTransaction(
  serializedTxBase64: string,
  programId: PublicKey,
  opts?: { expectedRecipientOwner?: string; expectedMint?: string }
): DecodedVaultSolanaTx {
  try {
    const raw = Buffer.from(serializedTxBase64, "base64");
    if (raw.length === 0) {
      throw new Error("empty transaction bytes");
    }
    const tx = Transaction.from(raw);
    const paymaster = tx.feePayer ? tx.feePayer.toBase58() : undefined;

    const unknownOuterPrograms: string[] = [];
    let createIx: { keys: PublicKey[]; inner: InnerMessage } | null = null;
    const approveIxs: { keys: PublicKey[] }[] = [];
    const executeTargets: string[] = [];

    for (const ix of tx.instructions) {
      const pid = ix.programId;
      const data = Buffer.from(ix.data);

      if (pid.equals(SystemProgram.programId)) {
        // Only nonceAdvance is an allowed outer SystemProgram instruction.
        if (
          data.length >= 4 &&
          data.readUInt32LE(0) === SYSTEM_IX_TAG_NONCE_ADVANCE
        ) {
          continue;
        }
        unknownOuterPrograms.push(pid.toBase58());
      } else if (pid.equals(ATA_PROGRAM_ID)) {
        // createAssociatedTokenAccount(Idempotent). A partial member signature
        // authorizes EVERY outer ix, so the rent FUNDER (keys[0]) must be the
        // fee payer / paymaster — otherwise a member leaf could be named as
        // funder and drained of its own lamports. Flag any other funder.
        const ataFunder =
          ix.keys.length > 0 ? ix.keys[0].pubkey.toBase58() : undefined;
        if (paymaster && ataFunder && ataFunder !== paymaster) {
          unknownOuterPrograms.push(pid.toBase58());
        }
        continue;
      } else if (pid.equals(programId)) {
        const disc = Uint8Array.from(data.subarray(0, 8));
        if (bytesEqual(disc, CREATE_TRANSACTION_DISCRIMINATOR)) {
          if (createIx) {
            throw new Error("multiple create_transaction instructions");
          }
          createIx = {
            keys: ix.keys.map((k) => k.pubkey),
            inner: parseCreateTransactionData(data),
          };
        } else if (bytesEqual(disc, APPROVE_TRANSACTION_DISCRIMINATOR)) {
          approveIxs.push({ keys: ix.keys.map((k) => k.pubkey) });
        } else if (bytesEqual(disc, EXECUTE_TRANSACTION_DISCRIMINATOR)) {
          // execute_transaction accounts: { multisig, transaction, executor }.
          // Capture its target proposal PDA (keys[1]) so the comparison can
          // bind it to the created / expected proposal (a swapped execute would
          // otherwise run a DIFFERENT proposal than the one shown).
          if (ix.keys.length >= 2) {
            executeTargets.push(ix.keys[1].pubkey.toBase58());
          }
        } else if (bytesEqual(disc, CLOSE_TRANSACTION_DISCRIMINATOR)) {
          // close_transaction only refunds rent to its stored payer (has_one) —
          // no fund movement to verify.
          continue;
        } else {
          // Multisig program with an unrecognized discriminator — fail closed.
          unknownOuterPrograms.push(pid.toBase58());
        }
      } else {
        unknownOuterPrograms.push(pid.toBase58());
      }
    }

    // Approve ix accounts: { multisig, transaction, member } (IDL order).
    // keys[1] = the proposal PDA the approval targets; keys[2] = the approving
    // member. Capture both — the target binds the signature to a specific
    // proposal (checked in compareDecodedToExpected).
    const approvers: string[] = [];
    const approveTargets: string[] = [];
    for (const a of approveIxs) {
      if (a.keys.length < 3) {
        throw new Error("approve_transaction instruction has too few accounts");
      }
      approveTargets.push(a.keys[1].toBase58());
      approvers.push(a.keys[2].toBase58());
    }

    if (createIx) {
      // Create ix accounts: { multisig, transaction, creator, payer,
      // systemProgram } (IDL order).
      if (createIx.keys.length < 3) {
        throw new Error("create_transaction instruction has too few accounts");
      }
      const inner = createIx.inner;
      if (inner.accountKeys.length === 0) {
        throw new Error("create_transaction inner message has no account keys");
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
            } else if (paymaster && dest === paymaster) {
              // Vault -> fee payer: a reimbursement, bucketed separately. This
              // is BOUNDED by compareDecodedToExpected (maxFeeLamports), so it
              // can no longer smuggle an unbounded vault drain to the fee payer.
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
              });
            }
          } else if (
            isTokenProgram &&
            d.length === 9 &&
            d[0] === SPL_IX_TAG_TRANSFER &&
            cix.accountIndexes.length >= 3
          ) {
            // Legacy Transfer: accounts [source, dest, authority];
            // data [tag u8, amount u64]. No mint/decimals on the wire.
            // AUTHORITY (accountIndexes[2]) must be the vault — see above.
            if (!resolve(cix.accountIndexes[2]).equals(inner.accountKeys[0])) {
              unknownInnerInstructionCount++;
            } else {
              const dest = resolve(cix.accountIndexes[1]).toBase58();
              recipients.push({
                address: dest,
                ata: dest,
                amount: readU64LE(d, 1).toString(),
                asset: "spl",
              });
            }
          } else {
            unknownInnerInstructionCount++;
          }
        } catch {
          unknownInnerInstructionCount++;
        }
      }

      // Optional ATA -> owner resolution for SPL recipients.
      if (opts?.expectedRecipientOwner && opts?.expectedMint) {
        const owner = new PublicKey(opts.expectedRecipientOwner);
        const mint = new PublicKey(opts.expectedMint);
        const candidates = [
          deriveAssociatedTokenAddress(
            owner,
            mint,
            TOKEN_PROGRAM_ID
          ).toBase58(),
          deriveAssociatedTokenAddress(
            owner,
            mint,
            TOKEN_2022_PROGRAM_ID
          ).toBase58(),
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

      return {
        kind: "create",
        vaultIndex: inner.vaultIndex,
        multisigPda: createIx.keys[0].toBase58(),
        transactionPda: createIx.keys[1].toBase58(),
        creator: createIx.keys[2].toBase58(),
        sender: inner.accountKeys[0].toBase58(),
        recipients,
        feeLamports: feeLamports.toString(),
        feePayer: paymaster ?? null,
        approvers,
        approveTargets,
        executeTargets,
        unknownInnerInstructionCount,
        unknownOuterPrograms,
      };
    }

    if (approveIxs.length > 0) {
      return {
        kind: "approve",
        multisigPda: approveIxs[0].keys[0].toBase58(),
        transactionPda: approveIxs[0].keys[1].toBase58(),
        approvers,
        approveTargets,
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
// Byte-decode vs relay-payload comparison
// ---------------------------------------------------------------------------

function toBigIntOrNull(value: string): bigint | null {
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

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
 *       base-unit amount match (matching on owner-or-ata address); every
 *       decoded recipient must be expected (extras = mismatch);
 *     • mint must equal expected.tokenMint when both present;
 *     • the vault→fee-payer reimbursement (`feeLamports`) must be <=
 *       `expected.maxFeeLamports` (DEFAULT 0 — any fee rejects unless the
 *       caller explicitly allows it) and, if `expected.expectedFeePayer` is
 *       set, be paid to that address. This closes the fee-laundering drain
 *       where a relay routes vault funds to the fee payer;
 *     • every bundled approve_transaction / execute_transaction must target the
 *       created proposal (and `expected.expectedTransactionPda` when set), so a
 *       signature cannot be harvested onto a different proposal;
 *     • any unknown outer program or unknown inner instruction = mismatch.
 * - kind "approve": an approve-only bundle carries NO proposal message, so its
 *   fund movement is not verifiable from these bytes. Rejected unless the caller
 *   sets `expected.approveOnlyVerifiedOnChain` (asserting it fetched and
 *   verified the on-chain VaultTransaction at `expected.expectedTransactionPda`).
 * - kind "undecodable": never ok.
 */
export function compareDecodedToExpected(
  decoded: DecodedVaultSolanaTx,
  expected: {
    recipients: Array<{ address: string; amount: string }>;
    tokenMint?: string;
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
     * Approve-only bundles have no message to verify. Set this ONLY after
     * independently fetching the on-chain VaultTransaction at
     * expectedTransactionPda and verifying its stored recipients/amounts;
     * expectedTransactionPda is required alongside it.
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

  if (decoded.kind === "approve") {
    // No proposal message in these bytes — bind the target if requested, then
    // fail closed unless the caller asserts an on-chain verification.
    for (const t of decoded.approveTargets) {
      if (
        expected.expectedTransactionPda &&
        t !== expected.expectedTransactionPda
      ) {
        mismatches.push(
          `approve_transaction targets ${t}, expected proposal ${expected.expectedTransactionPda}`
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

  if (decoded.unknownInnerInstructionCount > 0) {
    mismatches.push(
      `${decoded.unknownInnerInstructionCount} unrecognized inner instruction(s) in the transaction message`
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

  // Bound the vault→fee-payer reimbursement. Any outflow beyond the explicit
  // cap (default 0) is a mismatch — this is what stops the fee bucket smuggling
  // an unbounded vault drain past the recipient check.
  const decodedFee = toBigIntOrNull(decoded.feeLamports) ?? BigInt(0);
  const maxFee =
    expected.maxFeeLamports === undefined
      ? BigInt(0)
      : toBigIntOrNull(String(expected.maxFeeLamports));
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
    decoded.feePayer !== expected.expectedFeePayer
  ) {
    mismatches.push(
      `fee paid to ${decoded.feePayer ?? "unknown"}, expected fee payer ${
        expected.expectedFeePayer
      }`
    );
  }

  // Multiset match: every expected recipient must be found exactly once.
  const pool = decoded.recipients.map((r) => ({ recipient: r, used: false }));
  for (const exp of expected.recipients) {
    const expAmount = toBigIntOrNull(exp.amount);
    const index = pool.findIndex((entry) => {
      if (entry.used) return false;
      const r = entry.recipient;
      if (r.address !== exp.address && r.ata !== exp.address) return false;
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

  if (expected.tokenMint) {
    for (const r of decoded.recipients) {
      if (r.asset === "spl" && r.mint && r.mint !== expected.tokenMint) {
        mismatches.push(
          `decoded token mint ${r.mint} does not match expected mint ${expected.tokenMint}`
        );
      }
    }
  }

  return { ok: mismatches.length === 0, mismatches };
}
