/**
 * Regression tests for the 2026-10 security review of the Solana SDK decoder:
 *  - SOL-5 / CHN-3 / H-14: legacy SPL Transfer (tag 3) refused; asset, mint
 *    and decimals bound in the comparison.
 *  - SOL-7: the comparison binds the expected multisig / vault.
 *  - H-13 / SOL-3 / CHN-4: approve-only requests are verified against the
 *    on-chain VaultTransaction (fetchAndDecodeProposal + compare).
 *  - C-3 / SOL-1: fail-closed consumer 2-of-2 bundle gate.
 *
 * Offline: bundles are built with the SDK's own instruction builders and the
 * on-chain proposal account is encoded with Anchor's coder (independent of
 * the hand-rolled decoder) and served by a fake connection.
 */

import { strict as assert } from "assert";
import * as anchor from "@coral-xyz/anchor";
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  SolanaMultisigClient,
  buildMessageFromInstructions,
  deriveMultisigAddress,
  deriveNonceAccount,
  TransactionMessage,
} from "../src";
import {
  ATA_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  SolanaConnectionLike,
  compareDecodedToExpected,
  compareProposalToExpected,
  decodeVaultSolanaTransaction,
  decodeVaultTransactionAccount,
  deriveAssociatedTokenAddress,
  fetchAndDecodeProposal,
  verifyApproveOnlyTransaction,
  verifyConsumerSolanaBundle,
} from "../src/decoder";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const idl = require("../src/idl/solana_multisig.json");
const PROGRAM_ID = new PublicKey(idl.address);
const client = new SolanaMultisigClient(
  new Connection("http://localhost:8899"),
  PROGRAM_ID
);
const accountsCoder = new anchor.BorshAccountsCoder(idl);

// A web3.js Connection must satisfy the structural connection interface.
const _connectionTypeCheck: SolanaConnectionLike = new Connection(
  "http://localhost:8899"
);
void _connectionTypeCheck;

const walletMember = Keypair.generate();
const keyMember = Keypair.generate();
const otherMember = Keypair.generate();
const paymaster = Keypair.generate();
const recipientOwner = Keypair.generate();
const attacker = Keypair.generate();
const usdcMint = Keypair.generate().publicKey;
const bonkMint = Keypair.generate().publicKey;

const THRESHOLD = 2;
const [multisigPda] = deriveMultisigAddress(
  [walletMember.publicKey, keyMember.publicKey],
  THRESHOLD,
  PROGRAM_ID
);
const vaultPda = client.deriveVaultAddress(multisigPda, 0);
// Another vault the key leaf is also a member of (SOL-7 substitution target).
const [otherMultisigPda] = deriveMultisigAddress(
  [otherMember.publicKey, keyMember.publicKey],
  THRESHOLD,
  PROGRAM_ID
);
const otherVaultPda = client.deriveVaultAddress(otherMultisigPda, 0);

const SOL_AMOUNT = BigInt(1_500_000);
const TOKEN_AMOUNT = BigInt(2_500_000);
const FEE = BigInt(5000);
const DECIMALS = 6;

function transferChecked(opts: {
  vault: PublicKey;
  mint: PublicKey;
  owner: PublicKey;
  amount: bigint;
  decimals: number;
}): TransactionInstruction {
  const data = Buffer.alloc(10);
  data[0] = 12;
  data.writeBigUInt64LE(opts.amount, 1);
  data[9] = opts.decimals;
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      {
        pubkey: deriveAssociatedTokenAddress(opts.vault, opts.mint),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: opts.mint, isSigner: false, isWritable: false },
      {
        pubkey: deriveAssociatedTokenAddress(opts.owner, opts.mint),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: opts.vault, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function legacyTransfer(opts: {
  vault: PublicKey;
  mint: PublicKey;
  owner: PublicKey;
  amount: bigint;
}): TransactionInstruction {
  const data = Buffer.alloc(9);
  data[0] = 3;
  data.writeBigUInt64LE(opts.amount, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      {
        pubkey: deriveAssociatedTokenAddress(opts.vault, opts.mint),
        isSigner: false,
        isWritable: true,
      },
      {
        pubkey: deriveAssociatedTokenAddress(opts.owner, opts.mint),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: opts.vault, isSigner: true, isWritable: false },
    ],
    data,
  });
}

/** SPL SetAuthority(vault ATA → attacker): the C-3 hidden-instruction attack. */
function setAuthority(
  vault: PublicKey,
  mint: PublicKey,
  newAuthority: PublicKey
): TransactionInstruction {
  const data = Buffer.concat([Buffer.from([6, 2, 1]), newAuthority.toBuffer()]);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      {
        pubkey: deriveAssociatedTokenAddress(vault, mint),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: vault, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function reimburse(
  vault: PublicKey,
  lamports: bigint = FEE
): TransactionInstruction {
  return SystemProgram.transfer({
    fromPubkey: vault,
    toPubkey: paymaster.publicKey,
    lamports,
  });
}

function memo(text: string, keys: PublicKey[] = []): TransactionInstruction {
  return new TransactionInstruction({
    programId: MEMO_PROGRAM_ID,
    keys: keys.map((pubkey) => ({ pubkey, isSigner: true, isWritable: false })),
    data: Buffer.from(text, "utf8"),
  });
}

function ataCreate(
  owner: PublicKey,
  mint: PublicKey,
  funder: PublicKey = paymaster.publicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ATA_PROGRAM_ID,
    keys: [
      { pubkey: funder, isSigner: true, isWritable: true },
      {
        pubkey: deriveAssociatedTokenAddress(owner, mint),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]),
  });
}

interface BuiltBundle {
  base64: string;
  transactionAddress: PublicKey;
  message: TransactionMessage;
}

/** Wallet-style bundle: nonceAdvance, [priority], [outer extras], create, approve×2, execute, close. */
async function buildBundle(opts: {
  inner: TransactionInstruction[];
  multisig?: PublicKey;
  vault?: PublicKey;
  approvers?: PublicKey[];
  priority?: TransactionInstruction[];
  outerBeforeCreate?: TransactionInstruction[];
  outerAfter?: TransactionInstruction[];
  approveTarget?: PublicKey;
  feePayer?: PublicKey;
  currentTransactionIndex?: bigint;
  nonceFirst?: boolean;
}): Promise<BuiltBundle> {
  const multisig = opts.multisig ?? multisigPda;
  const vault = opts.vault ?? vaultPda;
  const message = buildMessageFromInstructions(vault, opts.inner);
  const {
    instruction: createIx,
    transactionAddress,
    transactionIndex,
  } = await client.buildCreateTransactionInstruction({
    multisigAddress: multisig,
    currentTransactionIndex: opts.currentTransactionIndex ?? BigInt(0),
    vaultIndex: 0,
    message,
    creator: walletMember.publicKey,
    payer: paymaster.publicKey,
  });
  const approves: TransactionInstruction[] = [];
  for (const member of opts.approvers ?? [
    walletMember.publicKey,
    keyMember.publicKey,
  ]) {
    approves.push(
      await client.buildApproveTransactionInstruction({
        multisigAddress: multisig,
        transactionAddress: opts.approveTarget ?? transactionAddress,
        transactionIndex,
        member,
      })
    );
  }
  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress: multisig,
    transactionAddress,
    transactionIndex,
    executor: walletMember.publicKey,
    // The decoder never reads execute's remaining accounts; omitted to keep
    // the fixture under the 1232-byte packet limit.
    remainingAccounts: [],
  });
  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress: multisig,
    transactionAddress,
    transactionIndex,
    payer: paymaster.publicKey,
  });
  const nonceAdvance = SystemProgram.nonceAdvance({
    noncePubkey: await deriveNonceAccount(multisig),
    authorizedPubkey: paymaster.publicKey,
  });
  const ixs = [
    ...(opts.priority ?? []),
    ...(opts.outerBeforeCreate ?? []),
    createIx,
    ...approves,
    executeIx,
    closeIx,
    ...(opts.outerAfter ?? []),
  ];
  if (opts.nonceFirst === false) ixs.splice(1, 0, nonceAdvance);
  else ixs.unshift(nonceAdvance);
  const tx = new Transaction().add(...ixs);
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.feePayer = opts.feePayer ?? paymaster.publicKey;
  return {
    base64: tx
      .serialize({ requireAllSignatures: false, verifySignatures: false })
      .toString("base64"),
    transactionAddress,
    message,
  };
}

/** Approve-only tx for a subsequent signer (split flow). */
async function buildApproveOnly(opts: {
  multisig?: PublicKey;
  target: PublicKey;
  transactionIndex: bigint;
  member?: PublicKey;
  extraApproveTarget?: PublicKey;
}): Promise<string> {
  const multisig = opts.multisig ?? multisigPda;
  const ixs: TransactionInstruction[] = [
    SystemProgram.nonceAdvance({
      noncePubkey: await deriveNonceAccount(multisig),
      authorizedPubkey: paymaster.publicKey,
    }),
    await client.buildApproveTransactionInstruction({
      multisigAddress: multisig,
      transactionAddress: opts.target,
      transactionIndex: opts.transactionIndex,
      member: opts.member ?? keyMember.publicKey,
    }),
  ];
  if (opts.extraApproveTarget) {
    ixs.push(
      await client.buildApproveTransactionInstruction({
        multisigAddress: multisig,
        transactionAddress: opts.extraApproveTarget,
        transactionIndex: opts.transactionIndex + BigInt(1),
        member: opts.member ?? keyMember.publicKey,
      })
    );
  }
  const tx = new Transaction().add(...ixs);
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.feePayer = paymaster.publicKey;
  return tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64");
}

function transactionPdaFor(multisig: PublicKey, index: bigint): PublicKey {
  return client.predictNextTransactionPda(multisig, index - BigInt(1))
    .transactionAddress;
}

/** Encode an on-chain VaultTransaction with Anchor's coder (independent of the decoder). */
async function encodeVaultTransaction(opts: {
  multisig: PublicKey;
  index: bigint;
  message: TransactionMessage;
  executed?: boolean;
  approvals?: PublicKey[];
}): Promise<Buffer> {
  const m = opts.message;
  return accountsCoder.encode("VaultTransaction", {
    multisig: opts.multisig,
    transaction_index: new anchor.BN(opts.index.toString()),
    creator: walletMember.publicKey,
    payer: paymaster.publicKey,
    bump: 255,
    vault_index: 0,
    vault_bump: 255,
    executed: opts.executed ?? false,
    approvals: opts.approvals ?? [walletMember.publicKey],
    message: {
      num_signers: m.numSigners,
      num_writable_signers: m.numWritableSigners,
      num_writable_non_signers: m.numWritableNonSigners,
      account_keys: m.accountKeys,
      instructions: m.instructions.map((ix) => ({
        program_id_index: ix.programIdIndex,
        account_indexes: Buffer.from(ix.accountIndexes),
        data: Buffer.from(ix.data),
      })),
      address_table_lookups: [],
    },
  });
}

function fakeConnection(
  accounts: Record<string, { owner: PublicKey; data: Buffer }>
): SolanaConnectionLike {
  return {
    async getAccountInfo(pk: PublicKey) {
      return accounts[pk.toBase58()] ?? null;
    },
  };
}

const usdcPayload = {
  recipients: [
    {
      address: recipientOwner.publicKey.toBase58(),
      amount: TOKEN_AMOUNT.toString(),
    },
  ],
  tokenMint: usdcMint.toBase58(),
  maxFeeLamports: FEE.toString(),
};

describe("security 2026-10: SOL-5 / CHN-3 token identity", function () {
  this.timeout(20000);

  it("PoC: legacy Transfer of USDC labelled as 'BONK' with relay decimals is refused", async function () {
    // [1] in the review: legacy Transfer(vault USDC ATA -> attacker USDC ATA, 1e12)
    // with relay payload tokenMint=<worthless>, decimals=12. Used to be ok:true.
    const attackerAta = deriveAssociatedTokenAddress(
      attacker.publicKey,
      usdcMint
    ).toBase58();
    const { base64 } = await buildBundle({
      inner: [
        legacyTransfer({
          vault: vaultPda,
          mint: usdcMint,
          owner: attacker.publicKey,
          amount: BigInt(1_000_000_000_000),
        }),
        reimburse(vaultPda),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients.length, 0);
    assert.equal(decoded.unknownInnerInstructionCount, 1);
    const cmp = compareDecodedToExpected(decoded, {
      recipients: [{ address: attackerAta, amount: "1000000000000" }],
      tokenMint: bonkMint.toBase58(),
      tokenDecimals: 12,
      maxFeeLamports: FEE.toString(),
    });
    assert.equal(cmp.ok, false);
    assert.ok(
      cmp.mismatches.some((m) => m.includes("unrecognized inner instruction"))
    );
  });

  it("TransferChecked: mint and decimals from the bytes are bound to the payload", async function () {
    const { base64 } = await buildBundle({
      inner: [
        transferChecked({
          vault: vaultPda,
          mint: usdcMint,
          owner: recipientOwner.publicKey,
          amount: TOKEN_AMOUNT,
          decimals: DECIMALS,
        }),
        reimburse(vaultPda),
      ],
    });
    // No ATA-owner opts: the compare resolves the owner from the derived ATA.
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients[0].mint, usdcMint.toBase58());
    assert.equal(decoded.recipients[0].decimals, DECIMALS);
    assert.equal(
      decoded.recipients[0].tokenProgram,
      TOKEN_PROGRAM_ID.toBase58()
    );

    assert.equal(compareDecodedToExpected(decoded, usdcPayload).ok, true);
    assert.equal(
      compareDecodedToExpected(decoded, {
        ...usdcPayload,
        tokenDecimals: DECIMALS,
      }).ok,
      true
    );

    const wrongDecimals = compareDecodedToExpected(decoded, {
      ...usdcPayload,
      tokenDecimals: 9,
    });
    assert.equal(wrongDecimals.ok, false);
    assert.ok(wrongDecimals.mismatches.some((m) => m.includes("decimals")));

    const wrongMint = compareDecodedToExpected(decoded, {
      ...usdcPayload,
      tokenMint: bonkMint.toBase58(),
    });
    assert.equal(wrongMint.ok, false);

    // An SPL transfer presented as a native SOL send.
    const asNative = compareDecodedToExpected(decoded, {
      recipients: usdcPayload.recipients,
      maxFeeLamports: FEE.toString(),
    });
    assert.equal(asNative.ok, false);
    assert.ok(
      asNative.mismatches.some((m) =>
        m.includes("expected payload is a native SOL transfer")
      )
    );
  });

  it("a native SOL transfer presented as a token transfer is refused", async function () {
    const { base64 } = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: TOKEN_AMOUNT,
        }),
        reimburse(vaultPda),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    const cmp = compareDecodedToExpected(decoded, usdcPayload);
    assert.equal(cmp.ok, false);
    assert.ok(
      cmp.mismatches.some((m) =>
        m.includes("expected payload is a token transfer")
      )
    );
  });

  it("fails closed on non-integer amounts and fee caps", async function () {
    const { base64 } = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        reimburse(vaultPda),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    const base = {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: SOL_AMOUNT.toString(),
        },
      ],
    };
    assert.equal(
      compareDecodedToExpected(decoded, {
        ...base,
        maxFeeLamports: FEE.toString(),
      }).ok,
      true
    );
    assert.equal(
      compareDecodedToExpected(decoded, { ...base, maxFeeLamports: "" }).ok,
      false
    );
    assert.equal(
      compareDecodedToExpected(decoded, { ...base, maxFeeLamports: "-1" }).ok,
      false
    );
    assert.equal(
      compareDecodedToExpected(decoded, {
        recipients: [
          { address: recipientOwner.publicKey.toBase58(), amount: "" },
        ],
        maxFeeLamports: FEE.toString(),
      }).ok,
      false
    );
  });
});

describe("security 2026-10: SOL-7 vault binding", function () {
  this.timeout(20000);

  it("refuses a create bundle for a different multisig/vault than expected", async function () {
    // The relay substitutes another vault the key leaf is also a member of.
    const { base64 } = await buildBundle({
      multisig: otherMultisigPda,
      vault: otherVaultPda,
      inner: [
        SystemProgram.transfer({
          fromPubkey: otherVaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        reimburse(otherVaultPda),
      ],
      approvers: [otherMember.publicKey, keyMember.publicKey],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    const expected = {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: SOL_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE.toString(),
    };
    // Without the binding the substitution is invisible...
    assert.equal(compareDecodedToExpected(decoded, expected).ok, true);
    // ...with it, it is refused.
    const bound = compareDecodedToExpected(decoded, {
      ...expected,
      expectedMultisigPda: multisigPda.toBase58(),
      expectedVaultPda: vaultPda.toBase58(),
      expectedVaultIndex: 0,
    });
    assert.equal(bound.ok, false);
    assert.ok(
      bound.mismatches.some((m) => m.includes("expected vault multisig"))
    );
    assert.ok(
      bound.mismatches.some((m) =>
        m.includes("does not match the expected vault")
      )
    );

    const correct = compareDecodedToExpected(decoded, {
      ...expected,
      expectedMultisigPda: otherMultisigPda.toBase58(),
      expectedVaultPda: otherVaultPda.toBase58(),
      expectedVaultIndex: 0,
    });
    assert.equal(correct.ok, true);
  });

  it("refuses an approve-only bundle for a different multisig, or with mixed targets", async function () {
    const target = transactionPdaFor(otherMultisigPda, BigInt(1));
    const base64 = await buildApproveOnly({
      multisig: otherMultisigPda,
      target,
      transactionIndex: BigInt(1),
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "approve");
    if (decoded.kind !== "approve") return;
    assert.equal(decoded.transactionIndex, "1");
    const cmp = compareDecodedToExpected(decoded, {
      recipients: [],
      approveOnlyVerifiedOnChain: true,
      expectedTransactionPda: target.toBase58(),
      expectedMultisigPda: multisigPda.toBase58(),
    });
    assert.equal(cmp.ok, false);

    const mine = transactionPdaFor(multisigPda, BigInt(1));
    const other = transactionPdaFor(multisigPda, BigInt(2));
    const mixed = await buildApproveOnly({
      target: mine,
      transactionIndex: BigInt(1),
      extraApproveTarget: other,
    });
    const decodedMixed = decodeVaultSolanaTransaction(mixed, PROGRAM_ID);
    const cmpMixed = compareDecodedToExpected(decodedMixed, {
      recipients: [],
      approveOnlyVerifiedOnChain: true,
      expectedTransactionPda: mine.toBase58(),
    });
    assert.equal(cmpMixed.ok, false);
    assert.ok(
      cmpMixed.mismatches.some((m) => m.includes("not the bundle's proposal"))
    );
  });
});

describe("security 2026-10: outer ComputeBudget and inner Memo (opt-in)", function () {
  this.timeout(20000);
  const priority = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50_000 }),
  ];

  it("ComputeBudget stays an unknown outer program unless allowed within caps", async function () {
    const { base64 } = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
      ],
      priority,
    });
    const strict = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(strict.kind, "create");
    if (strict.kind !== "create") return;
    assert.equal(strict.unknownOuterPrograms.length, 2);

    const allowed = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      allowComputeBudget: {
        maxUnitLimit: 400_000,
        maxUnitPriceMicroLamports: 100_000,
      },
    });
    if (allowed.kind !== "create") throw new Error("expected create");
    assert.deepEqual(allowed.unknownOuterPrograms, []);

    const capped = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      allowComputeBudget: {
        maxUnitLimit: 400_000,
        maxUnitPriceMicroLamports: 10_000,
      },
    });
    if (capped.kind !== "create") throw new Error("expected create");
    assert.equal(capped.unknownOuterPrograms.length, 1);

    const dup = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
      ],
      priority: [
        ...priority,
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
      ],
    });
    const decodedDup = decodeVaultSolanaTransaction(dup.base64, PROGRAM_ID, {
      allowComputeBudget: {},
    });
    if (decodedDup.kind !== "create") throw new Error("expected create");
    assert.equal(decodedDup.unknownOuterPrograms.length, 1);
  });

  it("Memo v2 without accounts is surfaced when allowed, unknown otherwise", async function () {
    const { base64 } = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        memo("invoice 42"),
      ],
    });
    const strict = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    if (strict.kind !== "create") throw new Error("expected create");
    assert.equal(strict.unknownInnerInstructionCount, 1);
    const allowed = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      allowMemo: true,
    });
    if (allowed.kind !== "create") throw new Error("expected create");
    assert.equal(allowed.unknownInnerInstructionCount, 0);
    assert.deepEqual(allowed.memos, ["invoice 42"]);

    const withAccounts = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        memo("x", [vaultPda]),
      ],
    });
    const decodedWithAccounts = decodeVaultSolanaTransaction(
      withAccounts.base64,
      PROGRAM_ID,
      { allowMemo: true }
    );
    if (decodedWithAccounts.kind !== "create")
      throw new Error("expected create");
    assert.equal(decodedWithAccounts.unknownInnerInstructionCount, 1);
  });
});

describe("security 2026-10: H-13 on-chain proposal verification (approve-only)", function () {
  this.timeout(20000);

  async function setup(opts: {
    inner: TransactionInstruction[];
    executed?: boolean;
    index?: bigint;
    multisig?: PublicKey;
    vault?: PublicKey;
  }) {
    const index = opts.index ?? BigInt(1);
    const multisig = opts.multisig ?? multisigPda;
    const message = buildMessageFromInstructions(
      opts.vault ?? vaultPda,
      opts.inner
    );
    const target = transactionPdaFor(multisig, index);
    const data = await encodeVaultTransaction({
      multisig,
      index,
      message,
      executed: opts.executed,
    });
    return { target, data, index, multisig };
  }

  const honestInner = () => [
    transferChecked({
      vault: vaultPda,
      mint: usdcMint,
      owner: recipientOwner.publicKey,
      amount: TOKEN_AMOUNT,
      decimals: DECIMALS,
    }),
    reimburse(vaultPda),
  ];

  it("decodes the stored message exactly like the bundle decoder", async function () {
    const { target, data } = await setup({ inner: honestInner() });
    const proposal = decodeVaultTransactionAccount(data, target, PROGRAM_ID);
    assert.equal(proposal.kind, "proposal");
    if (proposal.kind !== "proposal") return;
    assert.equal(proposal.multisigPda, multisigPda.toBase58());
    assert.equal(proposal.transactionIndex, "1");
    assert.equal(proposal.vaultPda, vaultPda.toBase58());
    assert.equal(proposal.sender, vaultPda.toBase58());
    assert.equal(proposal.executed, false);
    assert.deepEqual(proposal.approvals, [walletMember.publicKey.toBase58()]);
    assert.equal(proposal.feeLamports, FEE.toString());
    assert.equal(proposal.feePayer, paymaster.publicKey.toBase58());
    assert.equal(proposal.recipients.length, 1);
    assert.equal(proposal.recipients[0].mint, usdcMint.toBase58());
    assert.equal(proposal.recipients[0].decimals, DECIMALS);
    const cmp = compareProposalToExpected(proposal, {
      ...usdcPayload,
      tokenDecimals: DECIMALS,
      expectedMultisigPda: multisigPda.toBase58(),
      expectedFeePayer: paymaster.publicKey.toBase58(),
    });
    assert.deepEqual(cmp.mismatches, []);
    assert.equal(cmp.ok, true);
  });

  it("refuses a missing account, a foreign owner, a wrong discriminator and a non-canonical PDA", async function () {
    const { target, data } = await setup({ inner: honestInner() });
    const missing = await fetchAndDecodeProposal(
      fakeConnection({}),
      target,
      PROGRAM_ID
    );
    assert.equal(missing.kind, "undecodable");

    const foreign = await fetchAndDecodeProposal(
      fakeConnection({
        [target.toBase58()]: { owner: SystemProgram.programId, data },
      }),
      target,
      PROGRAM_ID
    );
    assert.equal(foreign.kind, "undecodable");

    const badDisc = Buffer.from(data);
    badDisc[0] ^= 0xff;
    assert.equal(
      decodeVaultTransactionAccount(badDisc, target, PROGRAM_ID).kind,
      "undecodable"
    );

    // Same bytes served at another address: not the canonical PDA.
    const elsewhere = Keypair.generate().publicKey;
    const moved = await fetchAndDecodeProposal(
      fakeConnection({ [elsewhere.toBase58()]: { owner: PROGRAM_ID, data } }),
      elsewhere,
      PROGRAM_ID
    );
    assert.equal(moved.kind, "undecodable");
    if (moved.kind === "undecodable")
      assert.ok(moved.error.includes("canonical"));

    assert.equal(
      compareProposalToExpected(missing, {
        ...usdcPayload,
        expectedMultisigPda: null,
      }).ok,
      false
    );
  });

  it("verifyApproveOnlyTransaction accepts an approve for the displayed proposal", async function () {
    const { target, data, index } = await setup({ inner: honestInner() });
    const base64 = await buildApproveOnly({ target, transactionIndex: index });
    const res = await verifyApproveOnlyTransaction({
      connection: fakeConnection({
        [target.toBase58()]: { owner: PROGRAM_ID, data },
      }),
      serializedTxBase64: base64,
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
      expectedApprover: keyMember.publicKey.toBase58(),
    });
    assert.deepEqual(res.mismatches, []);
    assert.equal(res.ok, true);
    assert.equal(res.proposal?.kind, "proposal");
  });

  it("PoC: relay steers the approval onto a different open proposal (drain) — refused", async function () {
    // The displayed payload is the benign USDC payment; the approve targets a
    // proposal that sends everything to the attacker.
    const { target, data, index } = await setup({
      inner: [
        transferChecked({
          vault: vaultPda,
          mint: usdcMint,
          owner: attacker.publicKey,
          amount: BigInt(1_000_000_000_000),
          decimals: DECIMALS,
        }),
        reimburse(vaultPda),
      ],
      index: BigInt(2),
    });
    const base64 = await buildApproveOnly({ target, transactionIndex: index });
    const res = await verifyApproveOnlyTransaction({
      connection: fakeConnection({
        [target.toBase58()]: { owner: PROGRAM_ID, data },
      }),
      serializedTxBase64: base64,
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
    });
    assert.equal(res.ok, false);
    assert.ok(
      res.mismatches.some((m) => m.includes("not found in decoded transaction"))
    );
  });

  it("refuses an executed proposal, a proposal of another vault, and a legacy-Transfer proposal", async function () {
    const executed = await setup({ inner: honestInner(), executed: true });
    const execRes = await verifyApproveOnlyTransaction({
      connection: fakeConnection({
        [executed.target.toBase58()]: {
          owner: PROGRAM_ID,
          data: executed.data,
        },
      }),
      serializedTxBase64: await buildApproveOnly({
        target: executed.target,
        transactionIndex: executed.index,
      }),
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
    });
    assert.equal(execRes.ok, false);
    assert.ok(
      execRes.mismatches.some((m) => m.includes("already been executed"))
    );

    const other = await setup({
      inner: [
        transferChecked({
          vault: otherVaultPda,
          mint: usdcMint,
          owner: recipientOwner.publicKey,
          amount: TOKEN_AMOUNT,
          decimals: DECIMALS,
        }),
        reimburse(otherVaultPda),
      ],
      multisig: otherMultisigPda,
      vault: otherVaultPda,
    });
    const otherRes = await verifyApproveOnlyTransaction({
      connection: fakeConnection({
        [other.target.toBase58()]: { owner: PROGRAM_ID, data: other.data },
      }),
      serializedTxBase64: await buildApproveOnly({
        multisig: otherMultisigPda,
        target: other.target,
        transactionIndex: other.index,
      }),
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
    });
    assert.equal(otherRes.ok, false);

    const legacy = await setup({
      inner: [
        legacyTransfer({
          vault: vaultPda,
          mint: usdcMint,
          owner: recipientOwner.publicKey,
          amount: TOKEN_AMOUNT,
        }),
        reimburse(vaultPda),
      ],
    });
    const legacyRes = await verifyApproveOnlyTransaction({
      connection: fakeConnection({
        [legacy.target.toBase58()]: { owner: PROGRAM_ID, data: legacy.data },
      }),
      serializedTxBase64: await buildApproveOnly({
        target: legacy.target,
        transactionIndex: legacy.index,
      }),
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
    });
    assert.equal(legacyRes.ok, false);
  });

  it("refuses a create bundle or undecodable bytes on the approve-only path", async function () {
    const { base64 } = await buildBundle({ inner: honestInner() });
    const res = await verifyApproveOnlyTransaction({
      connection: fakeConnection({}),
      serializedTxBase64: base64,
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: multisigPda.toBase58() },
    });
    assert.equal(res.ok, false);
    const garbage = await verifyApproveOnlyTransaction({
      connection: fakeConnection({}),
      serializedTxBase64: "not a tx",
      programId: PROGRAM_ID,
      expected: { ...usdcPayload, expectedMultisigPda: null },
    });
    assert.equal(garbage.ok, false);
  });
});

describe("security 2026-10: C-3 consumer bundle gate (verifyConsumerSolanaBundle)", function () {
  this.timeout(30000);
  const priority = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50_000 }),
  ];
  const baseParams = {
    programId: PROGRAM_ID,
    multisigPda: multisigPda.toBase58(),
    members: [
      walletMember.publicKey.toBase58(),
      keyMember.publicKey.toBase58(),
    ],
    signer: keyMember.publicKey.toBase58(),
    maxFeeLamports: FEE.toString(),
    expectedFeePayer: paymaster.publicKey.toBase58(),
    maxComputeUnitLimit: 400_000,
    maxComputeUnitPriceMicroLamports: 1_000_000,
  };
  const solExpected = {
    recipient: recipientOwner.publicKey.toBase58(),
    amount: SOL_AMOUNT.toString(),
  };
  const splExpected = {
    recipient: recipientOwner.publicKey.toBase58(),
    amount: TOKEN_AMOUNT.toString(),
    tokenMint: usdcMint.toBase58(),
    tokenDecimals: DECIMALS,
  };
  const solInner = () => [
    SystemProgram.transfer({
      fromPubkey: vaultPda,
      toPubkey: recipientOwner.publicKey,
      lamports: SOL_AMOUNT,
    }),
    reimburse(vaultPda),
  ];
  const splInner = () => [
    transferChecked({
      vault: vaultPda,
      mint: usdcMint,
      owner: recipientOwner.publicKey,
      amount: TOKEN_AMOUNT,
      decimals: DECIMALS,
    }),
    reimburse(vaultPda),
    memo("thanks"),
  ];

  it("accepts the honest native and SPL wallet bundles", async function () {
    const sol = await buildBundle({ inner: solInner(), priority });
    const solRes = verifyConsumerSolanaBundle(sol.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.deepEqual(solRes.mismatches, []);
    assert.equal(solRes.ok, true);
    assert.equal(solRes.decoded?.computeUnitPriceMicroLamports, "50000");

    const spl = await buildBundle({
      inner: splInner(),
      priority,
      outerBeforeCreate: [ataCreate(recipientOwner.publicKey, usdcMint)],
    });
    const splRes = verifyConsumerSolanaBundle(spl.base64, {
      ...baseParams,
      expected: splExpected,
    });
    assert.deepEqual(splRes.mismatches, []);
    assert.equal(splRes.ok, true);
    assert.deepEqual(splRes.decoded?.memos, ["thanks"]);
    assert.equal(
      splRes.decoded?.recipients[0].address,
      recipientOwner.publicKey.toBase58()
    );
  });

  it("PoC: hidden SetAuthority(vault USDC ATA -> attacker) behind a small SOL send is refused", async function () {
    const { base64 } = await buildBundle({
      inner: [
        ...solInner(),
        setAuthority(vaultPda, usdcMint, attacker.publicKey),
      ],
      priority,
    });
    const res = verifyConsumerSolanaBundle(base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(res.ok, false);
    assert.ok(
      res.mismatches.some((m) => m.includes("unrecognized inner instruction"))
    );
  });

  it("PoC: an appended approve_transaction(K) for a pre-created drain proposal is refused", async function () {
    const drainProposal = transactionPdaFor(multisigPda, BigInt(7));
    const extraApprove = await client.buildApproveTransactionInstruction({
      multisigAddress: multisigPda,
      transactionAddress: drainProposal,
      transactionIndex: BigInt(7),
      member: keyMember.publicKey,
    });
    const { base64 } = await buildBundle({
      inner: solInner(),
      priority,
      outerAfter: [extraApprove],
    });
    const res = verifyConsumerSolanaBundle(base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(res.ok, false);
    assert.ok(
      res.mismatches.some((m) => m.includes("not the created proposal"))
    );
  });

  it("refuses foreign outer instructions, a second create, and a misplaced nonceAdvance", async function () {
    const foreign = await buildBundle({
      inner: solInner(),
      outerAfter: [
        SystemProgram.transfer({
          fromPubkey: keyMember.publicKey,
          toPubkey: attacker.publicKey,
          lamports: 1,
        }),
      ],
    });
    assert.equal(
      verifyConsumerSolanaBundle(foreign.base64, {
        ...baseParams,
        expected: solExpected,
      }).ok,
      false
    );

    const second = await client.buildCreateTransactionInstruction({
      multisigAddress: multisigPda,
      currentTransactionIndex: BigInt(1),
      vaultIndex: 0,
      message: buildMessageFromInstructions(vaultPda, [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: attacker.publicKey,
          lamports: BigInt(10) ** BigInt(12),
        }),
      ]),
      creator: walletMember.publicKey,
      payer: paymaster.publicKey,
    });
    const twoCreates = await buildBundle({
      inner: solInner(),
      outerAfter: [second.instruction],
    });
    const twoRes = verifyConsumerSolanaBundle(twoCreates.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(twoRes.ok, false);
    assert.ok(
      twoRes.mismatches.some((m) =>
        m.includes("exactly one create_transaction")
      )
    );

    const misplaced = await buildBundle({
      inner: solInner(),
      priority,
      nonceFirst: false,
    });
    const misRes = verifyConsumerSolanaBundle(misplaced.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(misRes.ok, false);
    assert.ok(misRes.mismatches.some((m) => m.includes("must be first")));
  });

  it("refuses legacy Transfer, wrong mint/decimals/amount/recipient and an uncapped fee", async function () {
    const legacy = await buildBundle({
      inner: [
        legacyTransfer({
          vault: vaultPda,
          mint: usdcMint,
          owner: recipientOwner.publicKey,
          amount: TOKEN_AMOUNT,
        }),
        reimburse(vaultPda),
      ],
    });
    assert.equal(
      verifyConsumerSolanaBundle(legacy.base64, {
        ...baseParams,
        expected: splExpected,
      }).ok,
      false
    );

    const spl = await buildBundle({ inner: splInner() });
    assert.equal(
      verifyConsumerSolanaBundle(spl.base64, {
        ...baseParams,
        expected: splExpected,
      }).ok,
      true
    );
    assert.equal(
      verifyConsumerSolanaBundle(spl.base64, {
        ...baseParams,
        expected: { ...splExpected, tokenMint: bonkMint.toBase58() },
      }).ok,
      false
    );
    assert.equal(
      verifyConsumerSolanaBundle(spl.base64, {
        ...baseParams,
        expected: { ...splExpected, tokenDecimals: 9 },
      }).ok,
      false
    );
    assert.equal(
      verifyConsumerSolanaBundle(spl.base64, {
        ...baseParams,
        expected: { ...splExpected, amount: "1" },
      }).ok,
      false
    );
    assert.equal(
      verifyConsumerSolanaBundle(spl.base64, {
        ...baseParams,
        expected: { ...splExpected, recipient: attacker.publicKey.toBase58() },
      }).ok,
      false
    );

    const drain = await buildBundle({
      inner: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        reimburse(vaultPda, BigInt(99_000_000)),
      ],
    });
    const drainRes = verifyConsumerSolanaBundle(drain.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(drainRes.ok, false);
    assert.ok(
      drainRes.mismatches.some((m) => m.includes("exceeds the allowed maximum"))
    );
  });

  it("refuses a member as fee payer, an over-cap priority fee and a substituted vault", async function () {
    const memberPays = await buildBundle({
      inner: solInner(),
      priority,
      feePayer: keyMember.publicKey,
    });
    const memberRes = verifyConsumerSolanaBundle(memberPays.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(memberRes.ok, false);
    assert.ok(
      memberRes.mismatches.some((m) => m.includes("is a vault member"))
    );

    const expensive = await buildBundle({
      inner: solInner(),
      priority: [
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50_000_000 }),
      ],
    });
    assert.equal(
      verifyConsumerSolanaBundle(expensive.base64, {
        ...baseParams,
        expected: solExpected,
      }).ok,
      false
    );

    const substituted = await buildBundle({
      multisig: otherMultisigPda,
      vault: otherVaultPda,
      inner: [
        SystemProgram.transfer({
          fromPubkey: otherVaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: SOL_AMOUNT,
        }),
        reimburse(otherVaultPda),
      ],
      approvers: [keyMember.publicKey],
    });
    const subRes = verifyConsumerSolanaBundle(substituted.base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(subRes.ok, false);
    assert.ok(subRes.mismatches.some((m) => m.includes("names multisig")));
  });

  it("refuses an ATA create that does not match the recipient's token account", async function () {
    const wrongOwner = await buildBundle({
      inner: splInner(),
      outerBeforeCreate: [ataCreate(attacker.publicKey, usdcMint)],
    });
    assert.equal(
      verifyConsumerSolanaBundle(wrongOwner.base64, {
        ...baseParams,
        expected: splExpected,
      }).ok,
      false
    );

    const memberFunded = await buildBundle({
      inner: splInner(),
      outerBeforeCreate: [
        ataCreate(recipientOwner.publicKey, usdcMint, keyMember.publicKey),
      ],
    });
    assert.equal(
      verifyConsumerSolanaBundle(memberFunded.base64, {
        ...baseParams,
        expected: splExpected,
      }).ok,
      false
    );
  });

  it("refuses a bundle that does not carry the signer's own approval", async function () {
    const { base64 } = await buildBundle({
      inner: solInner(),
      approvers: [walletMember.publicKey],
    });
    const res = verifyConsumerSolanaBundle(base64, {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(res.ok, false);
    assert.ok(
      res.mismatches.some((m) => m.includes("no approval by the signer"))
    );
  });

  it("never throws on garbage and refuses a signer that is not a member", async function () {
    const garbage = verifyConsumerSolanaBundle("%%%", {
      ...baseParams,
      expected: solExpected,
    });
    assert.equal(garbage.ok, false);
    const sol = await buildBundle({ inner: solInner() });
    const notMember = verifyConsumerSolanaBundle(sol.base64, {
      ...baseParams,
      signer: attacker.publicKey.toBase58(),
      expected: solExpected,
    });
    assert.equal(notMember.ok, false);
  });
});
