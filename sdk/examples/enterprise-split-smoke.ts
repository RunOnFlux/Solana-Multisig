/**
 * Enterprise split-approval smoke test — self-contained, NO relay or DB needed.
 *
 * Reproduces the three split-flow transaction shapes from
 * SOLANA_SPLIT_APPROVAL_PLAN §3 that the enterprise backend will build for an
 * M-of-N Solana vault that is too large for the bundled flow (M_eff + 1 > 5):
 *
 *   1. Creator tx  = nonceAdvance(poolNonce) + create_transaction(creator=
 *      signer.wallet, payer=paymaster) + approve(signer.wallet)
 *      [+ approve(signer.key) dual]
 *   2. Approval tx = nonceAdvance(poolNonce) + approve(signer.wallet)
 *      [+ approve(signer.key) dual]
 *   3. Execute tx  = [createATAIdempotent if SPL] + execute_transaction(
 *      executor=paymaster) + close_transaction(payer=paymaster)
 *
 * Validates, at the worst-case enterprise cap (M = N = 15, sol_dual):
 *   - Each of the three tx shapes serializes to fewer than 1232 bytes (the
 *     Solana wire budget) with `requireAllSignatures:false`.
 *   - The creator tx uses the inner-message worst case: an SPL TransferChecked
 *     transfer + SOL reimburse + an 80-byte memo. Because the inner message is
 *     independent of M (it is an ix arg, not a per-signer account), the creator
 *     tx size does NOT grow with M — it fits at ANY M ≤ 15.
 *   - The execute tx carries the SPL createIdempotent ATA ix (ATA rent rides
 *     execute, paid only if the proposal executes).
 *
 * This test does NOT submit to devnet. It only exercises the off-chain
 * assembly + serialization pipeline, mirroring `enterprise-bundle-smoke.ts`.
 *
 * Run:
 *   tsx examples/enterprise-split-smoke.ts
 *   (or: ts-node --transpile-only examples/enterprise-split-smoke.ts)
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { SolanaMultisigClient } from "../src/client";
import {
  deriveMultisigAddress,
  deriveVaultAddress,
  deriveNonceAccount,
} from "../src/utils";
// TransactionMessage is defined (and exported) in ../src/types; client.ts only
// re-uses it internally without re-exporting, so import it from the source of
// truth to keep a standalone `tsc --noEmit` on this file clean.
import type { TransactionMessage } from "../src/types";

// Program ID matches the deployed devnet build of solana-multisig.
const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
);
const DEVNET_RPC = "https://api.devnet.solana.com";

// Wire budget — Solana packet max. Each split tx MUST fit under this.
const WIRE_BUDGET_BYTES = 1232;

// SPL token programs (constants only — no @solana/spl-token dependency; the ATA
// createIdempotent ix is a single-byte instruction we build by hand to keep
// this example self-contained, matching the SDK's zero-dep policy).
const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
);
const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
);
// SPL Memo v2 — same constant used in the production builder.
const MEMO_PROGRAM_ID = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
);

// Worst-case memo length (bytes) per the doc's ceiling computation.
const WORST_CASE_MEMO_BYTES = 80;

interface SspSigner {
  wkIdentity: string;
  wallet: Keypair;
  key: Keypair;
}

function sortByPubkeyBytes(pubkeys: PublicKey[]): PublicKey[] {
  return [...pubkeys].sort((a, b) => {
    const ba = a.toBytes();
    const bb = b.toBytes();
    for (let i = 0; i < 32; i++) {
      if (ba[i] !== bb[i]) return ba[i] - bb[i];
    }
    return 0;
  });
}

/**
 * Build a createAssociatedTokenAccountIdempotent instruction by hand.
 * Matches @solana/spl-token's builder: programId = ASSOCIATED_TOKEN_PROGRAM,
 * data = [1] (idempotent variant), keys =
 *   [payer(s,w), ata(w), owner(ro), mint(ro), SystemProgram(ro), TokenProgram(ro)].
 */
function buildCreateAtaIdempotentIx(
  payer: PublicKey,
  associatedToken: PublicKey,
  owner: PublicKey,
  mint: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: associatedToken, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]),
  });
}

/**
 * Worst-case creator inner message: SPL TransferChecked (vaultATA → recipientATA)
 * + SOL reimburse (vault → paymaster) + an 80-byte memo. This is the largest
 * inner message the creator tx can carry (SPL needs more accounts than SOL).
 * The ATA-create ix is NOT here — it rides the execute tx (§3).
 *
 * account_keys layout:
 *   0 vault         signer, writable   (the transfer authority)
 *   1 vaultAta      writable non-signer
 *   2 recipientAta  writable non-signer
 *   3 paymaster     writable non-signer (reimburse dest)
 *   4 mint          readonly non-signer
 *   5 TokenProgram  readonly non-signer
 *   6 SystemProgram readonly non-signer
 *   7 MemoProgram   readonly non-signer
 */
function buildInnerSplMessage(
  vaultPda: PublicKey,
  vaultAta: PublicKey,
  recipientAta: PublicKey,
  paymaster: PublicKey,
  mint: PublicKey,
  amount: bigint,
  decimals: number,
  reimburseLamports: bigint,
  memoText: string
): TransactionMessage {
  const reimburseIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: paymaster,
    lamports: reimburseLamports,
  });
  // TransferChecked data: [12, amount(u64 LE), decimals(u8)] = 10 bytes.
  const tcData = Buffer.alloc(10);
  tcData[0] = 12;
  tcData.writeBigUInt64LE(amount, 1);
  tcData[9] = decimals;

  const accountKeys: PublicKey[] = [
    vaultPda, // 0
    vaultAta, // 1
    recipientAta, // 2
    paymaster, // 3
    mint, // 4
    TOKEN_PROGRAM_ID, // 5
    SystemProgram.programId, // 6
    MEMO_PROGRAM_ID, // 7
  ];
  const instructions = [
    // TransferChecked: source(vaultAta=1), mint(4), dest(recipientAta=2), authority(vault=0)
    {
      programIdIndex: 5,
      accountIndexes: new Uint8Array([1, 4, 2, 0]),
      data: new Uint8Array(tcData),
    },
    // reimburse SOL: vault(0) → paymaster(3)
    {
      programIdIndex: 6,
      accountIndexes: new Uint8Array([0, 3]),
      data: new Uint8Array(reimburseIx.data),
    },
    // memo (no accounts)
    {
      programIdIndex: 7,
      accountIndexes: new Uint8Array([]),
      data: new Uint8Array(Buffer.from(memoText, "utf8")),
    },
  ];
  return {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 3, // vaultAta, recipientAta, paymaster
    accountKeys,
    instructions,
    addressTableLookups: [],
  };
}

interface SizeResult {
  label: string;
  bytes: number;
  sigCount: number;
  ok: boolean;
  error: string | null;
}

function serializeAndMeasure(
  tx: Transaction,
  label: string,
  sigCount: number
): SizeResult {
  let bytes: Buffer;
  try {
    bytes = tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false,
    });
  } catch (e) {
    const msg = (e as Error).message;
    return { label, bytes: -1, sigCount, ok: false, error: msg };
  }
  const ok = bytes.length <= WIRE_BUDGET_BYTES;
  return { label, bytes: bytes.length, sigCount, ok, error: null };
}

async function smokeTest(M: number, mode: "sol_dual" | "sol_single") {
  const N = M; // worst case for wire budget: M = N
  const dual = mode === "sol_dual";
  console.log(
    `\n=== M=${M}/${N} ${mode} (worst-case SPL + ${WORST_CASE_MEMO_BYTES}B memo) ===`
  );

  // Generate N SSP signers + paymaster.
  const signers: SspSigner[] = Array.from({ length: N }, (_, i) => ({
    wkIdentity: `wk_${i.toString().padStart(2, "0")}`,
    wallet: Keypair.generate(),
    key: Keypair.generate(),
  }));
  const paymaster = Keypair.generate();

  // Compute ed25519 member set + threshold per signing mode.
  const memberPubkeys: PublicKey[] = [];
  for (const s of signers) {
    memberPubkeys.push(s.wallet.publicKey);
    if (dual) memberPubkeys.push(s.key.publicKey);
  }
  const sortedMembers = sortByPubkeyBytes(memberPubkeys);
  const threshold = dual ? M * 2 : M;
  const mEff = threshold;

  // PDAs — must match what solanaVaultDerivationService computes.
  const [multisigPda] = deriveMultisigAddress(
    sortedMembers,
    threshold,
    PROGRAM_ID
  );
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);
  console.log(`  multisigPda: ${multisigPda.toBase58()}`);
  console.log(`  vaultPda:    ${vaultPda.toBase58()}  (M_eff=${mEff})`);

  // Worst-case SPL inner message (TransferChecked + reimburse + 80B memo).
  const mint = Keypair.generate().publicKey;
  const vaultAta = Keypair.generate().publicKey;
  const recipientAta = Keypair.generate().publicKey;
  const recipientOwner = Keypair.generate().publicKey;
  const innerMessage = buildInnerSplMessage(
    vaultPda,
    vaultAta,
    recipientAta,
    paymaster.publicKey,
    mint,
    BigInt(1_000_000),
    6,
    BigInt(100_000),
    "x".repeat(WORST_CASE_MEMO_BYTES)
  );

  // Connect to devnet only for the nonce-derivation utility (no on-chain reads).
  const connection = new Connection(DEVNET_RPC, { commitment: "confirmed" });
  const client = new SolanaMultisigClient(connection, PROGRAM_ID);

  // Canonical signer order (wkIdentity ASC); each signer signs in its own tx.
  const designated = [...signers].sort((a, b) =>
    a.wkIdentity.localeCompare(b.wkIdentity)
  );

  // Build create_transaction at predicted index 1 (first send, currentIndex=0).
  const {
    instruction: createIx,
    transactionAddress,
    transactionIndex,
  } = await client.buildCreateTransactionInstruction({
    multisigAddress: multisigPda,
    currentTransactionIndex: BigInt(0),
    vaultIndex: 0,
    message: innerMessage,
    creator: designated[0].wallet.publicKey,
    payer: paymaster.publicKey,
  });
  console.log(`  txAccount:   ${transactionAddress.toBase58()}`);
  console.log(`  txIndex:     ${transactionIndex.toString()}`);

  // Pool nonce + nonceAdvance (placeholder; wire size is value-independent).
  // The split flow anchors member-signed txs to a paymaster POOL nonce — here
  // we reuse the deterministic derivation purely for a realistic account shape.
  const poolNonce = await deriveNonceAccount(multisigPda);
  const buildNonceAdvance = () =>
    SystemProgram.nonceAdvance({
      noncePubkey: poolNonce,
      authorizedPubkey: paymaster.publicKey,
    });

  const results: SizeResult[] = [];

  // ── 1. Creator tx: nonceAdvance + create + approve(wallet) [+ approve(key)] ──
  const creatorApproveIxs: TransactionInstruction[] = [];
  creatorApproveIxs.push(
    await client.buildApproveTransactionInstruction({
      multisigAddress: multisigPda,
      transactionAddress,
      transactionIndex,
      member: designated[0].wallet.publicKey,
    })
  );
  if (dual) {
    creatorApproveIxs.push(
      await client.buildApproveTransactionInstruction({
        multisigAddress: multisigPda,
        transactionAddress,
        transactionIndex,
        member: designated[0].key.publicKey,
      })
    );
  }
  const creatorTx = new Transaction().add(
    buildNonceAdvance(),
    createIx,
    ...creatorApproveIxs
  );
  creatorTx.recentBlockhash = "11111111111111111111111111111111";
  creatorTx.feePayer = paymaster.publicKey;
  // sigs: wallet [+ key] + paymaster
  const creatorSigCount = (dual ? 2 : 1) + 1;
  results.push(
    serializeAndMeasure(
      creatorTx,
      "creator (nonceAdvance+create+approve)",
      creatorSigCount
    )
  );

  // ── 2. Approval tx: nonceAdvance + approve(wallet) [+ approve(key)] ──
  // Use a SUBSEQUENT signer (designated[1]) for realism.
  const approver = designated[1];
  const subsequentApproveIxs: TransactionInstruction[] = [];
  subsequentApproveIxs.push(
    await client.buildApproveTransactionInstruction({
      multisigAddress: multisigPda,
      transactionAddress,
      transactionIndex,
      member: approver.wallet.publicKey,
    })
  );
  if (dual) {
    subsequentApproveIxs.push(
      await client.buildApproveTransactionInstruction({
        multisigAddress: multisigPda,
        transactionAddress,
        transactionIndex,
        member: approver.key.publicKey,
      })
    );
  }
  const approvalTx = new Transaction().add(
    buildNonceAdvance(),
    ...subsequentApproveIxs
  );
  approvalTx.recentBlockhash = "11111111111111111111111111111111";
  approvalTx.feePayer = paymaster.publicKey;
  const approvalSigCount = (dual ? 2 : 1) + 1;
  results.push(
    serializeAndMeasure(
      approvalTx,
      "approval (nonceAdvance+approve)",
      approvalSigCount
    )
  );

  // ── 3. Execute tx: createATAIdempotent + execute + close (paymaster only) ──
  const createAtaIx = buildCreateAtaIdempotentIx(
    paymaster.publicKey,
    recipientAta,
    recipientOwner,
    mint
  );
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    executor: paymaster.publicKey,
    // remainingAccounts mirror the SPL inner account_keys order.
    remainingAccounts: [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: recipientAta, isSigner: false, isWritable: true },
      { pubkey: paymaster.publicKey, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: MEMO_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    payer: paymaster.publicKey,
  });
  const executeTx = new Transaction().add(createAtaIx, executeIx, closeIx);
  executeTx.recentBlockhash = "11111111111111111111111111111111";
  executeTx.feePayer = paymaster.publicKey;
  results.push(
    serializeAndMeasure(executeTx, "execute (createATA+execute+close)", 1)
  );

  // Report + assert.
  console.log("  ─ tx sizes ─────────────────────────────────────────────");
  let allOk = true;
  for (const r of results) {
    if (!r.ok) {
      allOk = false;
      const detail =
        r.bytes < 0 ? `serialize error: ${r.error}` : `${r.bytes}B OVER BUDGET`;
      console.log(`    ✗ ${r.label.padEnd(40)} ${detail}`);
      continue;
    }
    const headroom = WIRE_BUDGET_BYTES - r.bytes;
    console.log(
      `    ✓ ${r.label.padEnd(40)} ${String(r.bytes).padStart(
        5
      )}B  (headroom ${String(headroom).padStart(4)}B, ${r.sigCount} sigs)`
    );
  }
  if (!allOk) {
    throw new Error(`M=${M}/${N} ${mode}: a split tx exceeded the wire budget`);
  }
  return { mode, M, N, results };
}

async function main() {
  console.log("Enterprise split-approval smoke test");
  console.log(`Wire budget: ${WIRE_BUDGET_BYTES} bytes`);
  console.log(
    "Topology (SOLANA_SPLIT_APPROVAL_PLAN §3): one small tx per SSP signer +"
  );
  console.log("one paymaster-only execute tx. Inner message is M-independent.");

  // Primary target: M = N = 15 dual — the enterprise split-flow ceiling.
  const runs = [
    await smokeTest(15, "sol_dual"),
    await smokeTest(15, "sol_single"),
  ];

  console.log("\n=== Summary (per tx shape) ===");
  console.log(
    `  ${"config".padEnd(18)}${"tx shape".padEnd(42)}${"bytes".padStart(
      7
    )}${"headroom".padStart(11)}`
  );
  for (const run of runs) {
    const cfg = `M=${run.M}/${run.N} ${run.mode}`;
    for (const r of run.results) {
      const headroom = WIRE_BUDGET_BYTES - r.bytes;
      console.log(
        `  ${cfg.padEnd(18)}${r.label.padEnd(42)}${String(r.bytes).padStart(
          7
        )}${String(headroom).padStart(11)}`
      );
    }
  }

  const everyTxOk = runs.every((run) =>
    run.results.every((r) => r.ok && r.bytes <= WIRE_BUDGET_BYTES)
  );
  if (everyTxOk) {
    console.log(
      `\n✓ All split tx shapes fit under ${WIRE_BUDGET_BYTES}B at M=15 dual + single (worst-case SPL + ${WORST_CASE_MEMO_BYTES}B memo).`
    );
  } else {
    console.log("\n✗ At least one split tx exceeded the wire budget.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\nSplit smoke test FAILED:", err);
  process.exit(1);
});
