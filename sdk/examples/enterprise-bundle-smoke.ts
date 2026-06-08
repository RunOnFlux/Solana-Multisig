/**
 * Enterprise bundled-tx smoke test — self-contained, NO relay or DB needed.
 *
 * Reproduces what `ssp-relay-enterprise/src/services/solanaVaultProposalBuilderService.ts`
 * (`buildSolanaProposal` + `buildSolanaSigningTx`) constructs for an
 * enterprise M-of-N Solana vault, then validates:
 *
 *   1. PDA derivation matches between the two build steps (no drift)
 *   2. Bundled tx serializes to fewer than 1232 bytes (Solana wire budget)
 *      at the worst-case enterprise caps: M=2 dual / M=4 single mode
 *   3. Each designated member's ed25519 key can partial-sign the bundle
 *      and produce a verifiable sig at the expected slot
 *   4. After every member + paymaster signs, `verifySignatures()` returns true
 *
 * This test does NOT submit to devnet. It only exercises the off-chain
 * assembly + cryptographic verification pipeline. To run live broadcast,
 * use `devnet-setup-endpoint-flow-test.ts` after this passes.
 *
 * Run:
 *   tsx examples/enterprise-bundle-smoke.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { SolanaMultisigClient } from "../src/client";
import {
  deriveMultisigAddress,
  deriveVaultAddress,
  deriveNonceAccount,
} from "../src/utils";
import type { TransactionMessage } from "../src/client";

// Program ID matches the deployed devnet build of solana-multisig.
const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
);
const DEVNET_RPC = "https://api.devnet.solana.com";

// Wire budget — Solana packet max. Bundled enterprise tx MUST fit under this.
const WIRE_BUDGET_BYTES = 1232;

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

// SPL Memo v2 — same constant used in production builder.
const MEMO_PROGRAM_ID_BASE58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

function buildInnerSolMessage(
  vaultPda: PublicKey,
  recipient: PublicKey,
  paymaster: PublicKey,
  amountLamports: bigint,
  paymasterFeeLamports: bigint,
  memoText?: string
): TransactionMessage {
  const transferIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: recipient,
    lamports: amountLamports,
  });
  const reimburseIx = SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: paymaster,
    lamports: paymasterFeeLamports,
  });
  const accountKeys: PublicKey[] = [
    vaultPda,
    recipient,
    paymaster,
    SystemProgram.programId,
  ];
  const instructions = [
    {
      programIdIndex: 3,
      accountIndexes: new Uint8Array([0, 1]),
      data: new Uint8Array(transferIx.data),
    },
    {
      programIdIndex: 3,
      accountIndexes: new Uint8Array([0, 2]),
      data: new Uint8Array(reimburseIx.data),
    },
  ];
  if (memoText) {
    accountKeys.push(new PublicKey(MEMO_PROGRAM_ID_BASE58));
    instructions.push({
      programIdIndex: accountKeys.length - 1,
      accountIndexes: new Uint8Array([]),
      data: new Uint8Array(Buffer.from(memoText, "utf8")),
    });
  }
  return {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 2,
    accountKeys,
    instructions,
    addressTableLookups: [],
  };
}

async function smokeTest(
  M: number,
  mode: "sol_dual" | "sol_single",
  opts?: { memo?: string }
) {
  const N = M; // worst case for wire budget: M=N
  const memoSuffix = opts?.memo ? ` +memo(${opts.memo.length}ch)` : "";
  const label = `M=${M}/${N} ${mode}${memoSuffix}`;
  console.log(`\n=== ${label} ===`);

  // Generate M SSP signers + paymaster + recipient.
  const signers: SspSigner[] = Array.from({ length: N }, (_, i) => ({
    wkIdentity: `wk_${i.toString().padStart(2, "0")}`,
    wallet: Keypair.generate(),
    key: Keypair.generate(),
  }));
  const paymaster = Keypair.generate();
  const recipient = Keypair.generate();

  // Compute ed25519 member set + threshold per signing mode.
  const memberPubkeys: PublicKey[] = [];
  for (const s of signers) {
    memberPubkeys.push(s.wallet.publicKey);
    if (mode === "sol_dual") memberPubkeys.push(s.key.publicKey);
  }
  const sortedMembers = sortByPubkeyBytes(memberPubkeys);
  const threshold = mode === "sol_dual" ? M * 2 : M;

  // PDAs — must match what the relay-enterprise's
  // solanaVaultDerivationService computes for the same inputs.
  const [multisigPda] = deriveMultisigAddress(
    sortedMembers,
    threshold,
    PROGRAM_ID
  );
  const [vaultPda] = deriveVaultAddress(multisigPda, 0, PROGRAM_ID);
  console.log(`  multisigPda: ${multisigPda.toBase58()}`);
  console.log(`  vaultPda:    ${vaultPda.toBase58()}`);

  // Build the inner proposal message (mirror of buildSolanaProposal SOL path).
  const innerMessage = buildInnerSolMessage(
    vaultPda,
    recipient.publicKey,
    paymaster.publicKey,
    BigInt(100_000_000),
    BigInt(100_000),
    opts?.memo
  );

  // Connect to devnet just for nonce derivation utility (no on-chain reads).
  const connection = new Connection(DEVNET_RPC, { commitment: "confirmed" });
  const client = new SolanaMultisigClient(connection, PROGRAM_ID);

  // Approver order: canonical (wkIdentity ASC), wallet first then key per signer.
  const designated = [...signers].sort((a, b) =>
    a.wkIdentity.localeCompare(b.wkIdentity)
  );
  const approverEntries: Array<{
    wkIdentity: string;
    role: "wallet" | "key";
    keypair: Keypair;
  }> = [];
  for (const s of designated) {
    approverEntries.push({
      wkIdentity: s.wkIdentity,
      role: "wallet",
      keypair: s.wallet,
    });
    if (mode === "sol_dual") {
      approverEntries.push({
        wkIdentity: s.wkIdentity,
        role: "key",
        keypair: s.key,
      });
    }
  }

  // For this smoke we don't have a real on-chain multisig; we build the ixs
  // as if multisig.transactionIndex = 0 (first send) — predict for index 1.
  // The SDK helper takes the CURRENT index and adds 1 internally.
  const { instruction: createIx, transactionAddress, transactionIndex } =
    await client.buildCreateTransactionInstruction({
      multisigAddress: multisigPda,
      currentTransactionIndex: BigInt(0),
      vaultIndex: 0,
      message: innerMessage,
      creator: approverEntries[0].keypair.publicKey,
      payer: paymaster.publicKey,
    });
  console.log(`  txAccount:   ${transactionAddress.toBase58()}`);
  console.log(`  txIndex:     ${transactionIndex.toString()}`);

  const approveIxs = await Promise.all(
    approverEntries.map((entry) =>
      client.buildApproveTransactionInstruction({
        multisigAddress: multisigPda,
        transactionAddress,
        transactionIndex,
        member: entry.keypair.publicKey,
      })
    )
  );
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    executor: paymaster.publicKey,
    remainingAccounts: [
      { pubkey: vaultPda, isSigner: false, isWritable: true },
      { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
      { pubkey: paymaster.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisigPda,
    transactionAddress,
    transactionIndex,
    payer: paymaster.publicKey,
  });

  // Durable nonce — we don't fetch the on-chain state for this smoke test;
  // use a deterministic placeholder blockhash. The bundled tx's wire size
  // doesn't depend on the actual nonce value, only the nonceAdvance ix shape.
  const nonceAccount = await deriveNonceAccount(multisigPda);
  const nonceAdvanceIx = SystemProgram.nonceAdvance({
    noncePubkey: nonceAccount,
    authorizedPubkey: paymaster.publicKey,
  });

  const tx = new Transaction().add(
    nonceAdvanceIx,
    createIx,
    ...approveIxs,
    executeIx,
    closeIx
  );
  // Stub blockhash — any base58-encoded 32-byte value works for serialization.
  tx.recentBlockhash = "11111111111111111111111111111111";
  tx.feePayer = paymaster.publicKey;

  // 1) Wire-budget check: serialize without sigs and assert under 1232 bytes.
  let unsignedBytes: Buffer;
  try {
    unsignedBytes = tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false,
    });
  } catch (e) {
    const msg = (e as Error).message;
    console.log(`  ✗ ${label} FAILED to serialize: ${msg}`);
    return { label, bytes: -1, sigCount: 0, ok: false, error: msg };
  }
  const expectedSigCount = 1 /* paymaster */ + approverEntries.length;
  console.log(`  unsignedBytes:   ${unsignedBytes.length} bytes`);
  console.log(`  withSigs (est):  ${unsignedBytes.length} (sig slots already counted)`);
  console.log(`  signerSlots:     ${expectedSigCount}`);
  if (unsignedBytes.length > WIRE_BUDGET_BYTES) {
    throw new Error(
      `${label}: wire budget exceeded (${unsignedBytes.length} > ${WIRE_BUDGET_BYTES})`
    );
  }

  // 2) Slot-map check: each approver pubkey must own a slot in tx.signatures.
  const slotByPubkey = new Map<string, number>();
  tx.signatures.forEach((s, idx) =>
    slotByPubkey.set(s.publicKey.toBase58(), idx)
  );
  for (const entry of approverEntries) {
    const slot = slotByPubkey.get(entry.keypair.publicKey.toBase58());
    if (slot === undefined) {
      throw new Error(
        `${label}: approver ${entry.wkIdentity}/${entry.role} not in sig slots`
      );
    }
  }
  const paymasterSlot = slotByPubkey.get(paymaster.publicKey.toBase58());
  if (paymasterSlot === undefined) {
    throw new Error(`${label}: paymaster not in sig slots`);
  }

  // 3) Per-member partial-sign — each approver signs independently. Mirrors
  //    what the wallet+key Solana branch does in EnterpriseVaultSignTx and
  //    ssp-key's vault sign action.
  const txForVerify = Transaction.from(unsignedBytes);
  for (const entry of approverEntries) {
    txForVerify.partialSign(entry.keypair);
  }
  txForVerify.partialSign(paymaster);
  if (!txForVerify.verifySignatures(true)) {
    throw new Error(`${label}: verifySignatures(true) returned false`);
  }

  console.log(`  ✓ ${label} passed (${expectedSigCount} sig slots, ${unsignedBytes.length}B)`);
  return {
    label,
    bytes: unsignedBytes.length,
    sigCount: expectedSigCount,
    ok: true,
    error: null as string | null,
  };
}

async function main() {
  console.log("Enterprise bundled-tx smoke test");
  console.log(`Wire budget: ${WIRE_BUDGET_BYTES} bytes`);
  const results = [];
  // Worst-case enterprise caps from solanaVaultDerivationService:
  //   sol_dual:   M ≤ 2
  //   sol_single: M ≤ 4
  // Boundary cases — caps empirically validated below. Anything above
  // these must FAIL serialization (the test asserts both pass + fail
  // expectations).
  results.push(await smokeTest(2, "sol_dual"));
  results.push(await smokeTest(2, "sol_single"));
  results.push(await smokeTest(3, "sol_single"));
  results.push(await smokeTest(4, "sol_single"));
  // Memo combinations — common use case + worst memo length at boundary.
  results.push(await smokeTest(2, "sol_dual", { memo: "Q1 invoice #1289" }));
  results.push(await smokeTest(4, "sol_single", { memo: "x".repeat(64) }));
  // The next two SHOULD fail serialization — proves caps are tight.
  results.push(await smokeTest(3, "sol_dual"));
  results.push(await smokeTest(5, "sol_single"));

  console.log("\n=== Summary ===");
  for (const r of results) {
    if (!r.ok) {
      console.log(`  ${r.label.padEnd(25)} EXCEEDS BUDGET — ${r.error}`);
      continue;
    }
    const headroom = WIRE_BUDGET_BYTES - r.bytes;
    console.log(
      `  ${r.label.padEnd(25)} ${r.bytes}B  (headroom: ${headroom}B, ${r.sigCount} sigs)`
    );
  }
  // Expected outcomes: the first 6 must pass (4 boundary + 2 memo), the last
  // 2 must fail (over-cap tests proving caps are tight, not arbitrary).
  const PASSING_CASES = 6;
  const passing = results.slice(0, PASSING_CASES);
  const overcapTests = results.slice(PASSING_CASES);
  const passingOk = passing.every((r) => r.ok);
  const overcapOk = overcapTests.every((r) => !r.ok);
  const allOk = passingOk && overcapOk;
  if (allOk) {
    console.log(
      `\n✓ All ${PASSING_CASES} within-cap cases passed; ${overcapTests.length} over-cap cases correctly rejected.`,
    );
  } else {
    console.log("\n✗ Smoke test outcome mismatch:");
    if (!passingOk) console.log("  expected pass cases failed");
    if (!overcapOk) console.log("  expected over-cap rejections passed (caps too loose)");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\nSmoke test FAILED:", err);
  process.exit(1);
});
