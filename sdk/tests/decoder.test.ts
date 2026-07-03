/**
 * Offline fixture-driven tests for the vault transaction decoder.
 *
 * Fixtures are built with the SDK's own instruction builders (client.ts
 * build* helpers are offline — no RPC calls) and composed EXACTLY like the
 * relay bundle builder (ssp-relay-enterprise
 * solanaVaultProposalBuilderService.ts):
 *
 *   new Transaction().add(nonceAdvanceIx, [ataCreateIx], createIx,
 *                         ...approveIxs, executeIx, closeIx)
 *   feePayer = paymaster, recentBlockhash = durable nonce value,
 *   serialize({ requireAllSignatures: false, verifySignatures: false })
 */

import { strict as assert } from "assert";
import {
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
  deriveNonceAccount,
  TransactionMessage,
} from "../src";
import {
  ATA_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  compareDecodedToExpected,
  decodeVaultSolanaTransaction,
  deriveAssociatedTokenAddress,
} from "../src/decoder";

// Anchor's Program takes its program id from the IDL `address` field, so the
// builders emit instructions for this id regardless of the client constructor
// argument — use it everywhere for consistency.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const idl = require("../src/idl/solana_multisig.json") as { address: string };
const PROGRAM_ID = new PublicKey(idl.address);

const client = new SolanaMultisigClient(
  new Connection("http://localhost:8899"),
  PROGRAM_ID
);

// Deterministic-ish actors for the whole suite.
const walletMember = Keypair.generate();
const keyMember = Keypair.generate();
const members = [walletMember, keyMember];
const paymaster = Keypair.generate();
const recipientOwner = Keypair.generate();
const mint = Keypair.generate().publicKey;

const THRESHOLD = 2;
const VAULT_INDEX = 0;
const NATIVE_AMOUNT = BigInt(1500000);
const SPL_AMOUNT = BigInt(2500000);
const FEE_LAMPORTS = BigInt(5000);
const DECIMALS = 6;

const multisigAddress = client.deriveAddress(
  members.map((m) => m.publicKey),
  THRESHOLD
);
const vaultPda = client.deriveVaultAddress(multisigAddress, VAULT_INDEX);

interface BundleFixture {
  base64: string;
  transactionAddress: PublicKey;
}

/**
 * Compose a full relay-style bundle:
 * nonceAdvance + [extra outer ixs] + [ata create] + create + approve x N +
 * execute + close.
 */
async function buildBundle(opts: {
  innerInstructions: TransactionInstruction[];
  includeAtaCreate?: boolean;
  extraOuterInstructions?: TransactionInstruction[];
  /** Make the approve_transaction ix(s) target a DIFFERENT proposal PDA. */
  approveTargetOverride?: PublicKey;
  /** Fund the ATA-create with this account instead of the paymaster. */
  ataFunder?: PublicKey;
}): Promise<BundleFixture> {
  const nonceAccount = await deriveNonceAccount(multisigAddress);
  const nonceAdvanceIx = SystemProgram.nonceAdvance({
    noncePubkey: nonceAccount,
    authorizedPubkey: paymaster.publicKey,
  });

  const message: TransactionMessage = buildMessageFromInstructions(
    vaultPda,
    opts.innerInstructions
  );

  const {
    instruction: createIx,
    transactionAddress,
    transactionIndex,
  } = await client.buildCreateTransactionInstruction({
    multisigAddress,
    currentTransactionIndex: BigInt(0),
    vaultIndex: VAULT_INDEX,
    message,
    creator: walletMember.publicKey,
    payer: paymaster.publicKey,
  });

  const approveIxs: TransactionInstruction[] = [];
  for (const member of members) {
    approveIxs.push(
      await client.buildApproveTransactionInstruction({
        multisigAddress,
        transactionAddress: opts.approveTargetOverride ?? transactionAddress,
        transactionIndex,
        member: member.publicKey,
      })
    );
  }

  const executeIx = await client.buildExecuteTransactionInstruction({
    multisigAddress,
    transactionAddress,
    transactionIndex,
    executor: paymaster.publicKey,
    remainingAccounts: message.accountKeys.map((pubkey) => ({
      pubkey,
      isSigner: false,
      isWritable: true,
    })),
  });

  const closeIx = await client.buildCloseTransactionInstruction({
    multisigAddress,
    transactionAddress,
    transactionIndex,
    payer: paymaster.publicKey,
  });

  const outerAtaIxs: TransactionInstruction[] = [];
  if (opts.includeAtaCreate) {
    // Shape of createAssociatedTokenAccountIdempotentInstruction without
    // pulling in @solana/spl-token as an sdk dependency — the decoder only
    // classifies by program id.
    outerAtaIxs.push(
      new TransactionInstruction({
        programId: ATA_PROGRAM_ID,
        keys: [
          {
            pubkey: opts.ataFunder ?? paymaster.publicKey,
            isSigner: true,
            isWritable: true,
          },
          {
            pubkey: deriveAssociatedTokenAddress(
              recipientOwner.publicKey,
              mint
            ),
            isSigner: false,
            isWritable: true,
          },
          {
            pubkey: recipientOwner.publicKey,
            isSigner: false,
            isWritable: false,
          },
          { pubkey: mint, isSigner: false, isWritable: false },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([1]),
      })
    );
  }

  const tx = new Transaction().add(
    nonceAdvanceIx,
    ...(opts.extraOuterInstructions ?? []),
    ...outerAtaIxs,
    createIx,
    ...approveIxs,
    executeIx,
    closeIx
  );
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.feePayer = paymaster.publicKey;

  const base64 = tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64");
  return { base64, transactionAddress };
}

/** Approve-only tx as built for subsequent signers in the split flow. */
async function buildApproveOnlyTx(): Promise<BundleFixture> {
  const nonceAccount = await deriveNonceAccount(multisigAddress);
  const nonceAdvanceIx = SystemProgram.nonceAdvance({
    noncePubkey: nonceAccount,
    authorizedPubkey: paymaster.publicKey,
  });
  const transactionIndex = BigInt(1);
  const { transactionAddress } = client.predictNextTransactionPda(
    multisigAddress,
    BigInt(0)
  );
  const approveIx = await client.buildApproveTransactionInstruction({
    multisigAddress,
    transactionAddress,
    transactionIndex,
    member: keyMember.publicKey,
  });

  const tx = new Transaction().add(nonceAdvanceIx, approveIx);
  tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
  tx.feePayer = paymaster.publicKey;
  const base64 = tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64");
  return { base64, transactionAddress };
}

function nativeInnerInstructions(): TransactionInstruction[] {
  return [
    SystemProgram.transfer({
      fromPubkey: vaultPda,
      toPubkey: recipientOwner.publicKey,
      lamports: NATIVE_AMOUNT,
    }),
    SystemProgram.transfer({
      fromPubkey: vaultPda,
      toPubkey: paymaster.publicKey,
      lamports: FEE_LAMPORTS,
    }),
  ];
}

function splTransferCheckedInstruction(): TransactionInstruction {
  const sourceAta = deriveAssociatedTokenAddress(vaultPda, mint);
  const destAta = deriveAssociatedTokenAddress(recipientOwner.publicKey, mint);
  const data = Buffer.alloc(10);
  data[0] = 12; // TransferChecked
  data.writeBigUInt64LE(SPL_AMOUNT, 1);
  data[9] = DECIMALS;
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: sourceAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: destAta, isSigner: false, isWritable: true },
      { pubkey: vaultPda, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function splLegacyTransferInstruction(): TransactionInstruction {
  const sourceAta = deriveAssociatedTokenAddress(vaultPda, mint);
  const destAta = deriveAssociatedTokenAddress(recipientOwner.publicKey, mint);
  const data = Buffer.alloc(9);
  data[0] = 3; // Transfer (legacy)
  data.writeBigUInt64LE(SPL_AMOUNT, 1);
  return new TransactionInstruction({
    programId: TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: sourceAta, isSigner: false, isWritable: true },
      { pubkey: destAta, isSigner: false, isWritable: true },
      { pubkey: vaultPda, isSigner: true, isWritable: false },
    ],
    data,
  });
}

function feeReimburseInstruction(): TransactionInstruction {
  return SystemProgram.transfer({
    fromPubkey: vaultPda,
    toPubkey: paymaster.publicKey,
    lamports: FEE_LAMPORTS,
  });
}

describe("deriveAssociatedTokenAddress", function () {
  it("matches @solana/spl-token getAssociatedTokenAddressSync", function () {
    // Cross-check the hand-rolled derivation against the reference
    // implementation (available from the repo root devDependencies).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const splToken = require("@solana/spl-token") as {
      getAssociatedTokenAddressSync: (
        mint: PublicKey,
        owner: PublicKey,
        allowOwnerOffCurve?: boolean,
        programId?: PublicKey
      ) => { toBase58: () => string };
    };
    const expected = splToken.getAssociatedTokenAddressSync(
      mint,
      recipientOwner.publicKey
    );
    assert.equal(
      deriveAssociatedTokenAddress(recipientOwner.publicKey, mint).toBase58(),
      expected.toBase58()
    );
  });
});

describe("decodeVaultSolanaTransaction", function () {
  this.timeout(20000);

  it("(a) decodes a native SOL bundle: sender, recipient, amount, fee, approvers, zero unknowns", async function () {
    const { base64, transactionAddress } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.vaultIndex, VAULT_INDEX);
    assert.equal(decoded.multisigPda, multisigAddress.toBase58());
    assert.equal(decoded.transactionPda, transactionAddress.toBase58());
    assert.equal(decoded.creator, walletMember.publicKey.toBase58());
    assert.equal(decoded.sender, vaultPda.toBase58());
    assert.equal(decoded.recipients.length, 1);
    assert.deepEqual(decoded.recipients[0], {
      address: recipientOwner.publicKey.toBase58(),
      amount: NATIVE_AMOUNT.toString(),
      asset: "native",
    });
    assert.equal(decoded.feeLamports, FEE_LAMPORTS.toString());
    assert.deepEqual(decoded.approvers, [
      walletMember.publicKey.toBase58(),
      keyMember.publicKey.toBase58(),
    ]);
    assert.equal(decoded.unknownInnerInstructionCount, 0);
    assert.deepEqual(decoded.unknownOuterPrograms, []);

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, true);
    assert.deepEqual(compared.mismatches, []);
  });

  it("(b) decodes SPL TransferChecked: mint + decimals from bytes, ATA owner verification", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: [
        splTransferCheckedInstruction(),
        feeReimburseInstruction(),
      ],
      includeAtaCreate: true,
    });
    const destAta = deriveAssociatedTokenAddress(
      recipientOwner.publicKey,
      mint
    ).toBase58();

    // Correct expected owner -> ataVerified true, address resolves to owner.
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      expectedRecipientOwner: recipientOwner.publicKey.toBase58(),
      expectedMint: mint.toBase58(),
    });
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients.length, 1);
    const recipient = decoded.recipients[0];
    assert.equal(recipient.asset, "spl");
    assert.equal(recipient.mint, mint.toBase58());
    assert.equal(recipient.decimals, DECIMALS);
    assert.equal(recipient.amount, SPL_AMOUNT.toString());
    assert.equal(recipient.ata, destAta);
    assert.equal(recipient.ataVerified, true);
    assert.equal(recipient.address, recipientOwner.publicKey.toBase58());
    assert.equal(decoded.feeLamports, FEE_LAMPORTS.toString());
    assert.equal(decoded.unknownInnerInstructionCount, 0);
    assert.deepEqual(decoded.unknownOuterPrograms, []);

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: SPL_AMOUNT.toString(),
        },
      ],
      tokenMint: mint.toBase58(),
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, true);

    // Wrong expected owner -> ataVerified false, address stays the raw ata.
    const wrongOwner = Keypair.generate().publicKey.toBase58();
    const decodedWrong = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      expectedRecipientOwner: wrongOwner,
      expectedMint: mint.toBase58(),
    });
    assert.equal(decodedWrong.kind, "create");
    if (decodedWrong.kind !== "create") return;
    assert.equal(decodedWrong.recipients[0].ataVerified, false);
    assert.equal(decodedWrong.recipients[0].address, destAta);

    // No opts -> verification not attempted.
    const decodedNoOpts = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decodedNoOpts.kind, "create");
    if (decodedNoOpts.kind !== "create") return;
    assert.equal(decodedNoOpts.recipients[0].ataVerified, undefined);
    assert.equal(decodedNoOpts.recipients[0].address, destAta);
  });

  it("(c) decodes legacy SPL Transfer (tag 3): mint and decimals undefined", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: [
        splLegacyTransferInstruction(),
        feeReimburseInstruction(),
      ],
    });
    const destAta = deriveAssociatedTokenAddress(
      recipientOwner.publicKey,
      mint
    ).toBase58();
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients.length, 1);
    const recipient = decoded.recipients[0];
    assert.equal(recipient.asset, "spl");
    assert.equal(recipient.mint, undefined);
    assert.equal(recipient.decimals, undefined);
    assert.equal(recipient.ata, destAta);
    assert.equal(recipient.address, destAta);
    assert.equal(recipient.amount, SPL_AMOUNT.toString());

    // Matching on the raw ata address works.
    const compared = compareDecodedToExpected(decoded, {
      recipients: [{ address: destAta, amount: SPL_AMOUNT.toString() }],
      tokenMint: mint.toBase58(), // mint not comparable (absent on the wire)
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, true);
  });

  it("(d) decodes an approve-only tx (split-flow subsequent signer)", async function () {
    const { base64, transactionAddress } = await buildApproveOnlyTx();
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "approve");
    if (decoded.kind !== "approve") return;
    assert.equal(decoded.multisigPda, multisigAddress.toBase58());
    assert.equal(decoded.transactionPda, transactionAddress.toBase58());
    assert.deepEqual(decoded.approvers, [keyMember.publicKey.toBase58()]);
    assert.deepEqual(decoded.unknownOuterPrograms, []);

    // Fail-closed: an approve-only bundle carries no message, so it can't be
    // content-verified from its bytes — the gate rejects by default.
    const blind = compareDecodedToExpected(decoded, { recipients: [] });
    assert.equal(blind.ok, false);
    assert.ok(blind.mismatches.some((m) => m.includes("approve-only")));

    // Caller asserts it verified the on-chain proposal + binds the target → ok.
    const acked = compareDecodedToExpected(decoded, {
      recipients: [],
      approveOnlyVerifiedOnChain: true,
      expectedTransactionPda: transactionAddress.toBase58(),
    });
    assert.equal(acked.ok, true);

    // Acknowledged, but the approve targets a DIFFERENT proposal than expected.
    const wrongTarget = compareDecodedToExpected(decoded, {
      recipients: [],
      approveOnlyVerifiedOnChain: true,
      expectedTransactionPda: Keypair.generate().publicKey.toBase58(),
    });
    assert.equal(wrongTarget.ok, false);
  });

  it("(e) flags a foreign outer instruction (leaf-key-drain guard)", async function () {
    const attacker = Keypair.generate().publicKey;
    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
      extraOuterInstructions: [
        SystemProgram.transfer({
          fromPubkey: walletMember.publicKey,
          toPubkey: attacker,
          lamports: BigInt(999999999),
        }),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.deepEqual(decoded.unknownOuterPrograms, [
      SystemProgram.programId.toBase58(),
    ]);

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
    assert.ok(
      compared.mismatches.some((m) => m.includes("unknown outer program"))
    );
  });

  it("(e2) flags an unknown discriminator on the multisig program itself", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
      extraOuterInstructions: [
        new TransactionInstruction({
          programId: PROGRAM_ID,
          keys: [
            {
              pubkey: walletMember.publicKey,
              isSigner: true,
              isWritable: true,
            },
          ],
          data: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9]),
        }),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.deepEqual(decoded.unknownOuterPrograms, [PROGRAM_ID.toBase58()]);
  });

  it("(f) reports mismatches for tampered amount / recipient / extras", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");

    // Tampered amount. (maxFeeLamports set so the fee is not itself a mismatch.)
    const wrongAmount = compareDecodedToExpected(decoded, {
      recipients: [
        { address: recipientOwner.publicKey.toBase58(), amount: "1" },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(wrongAmount.ok, false);
    assert.equal(wrongAmount.mismatches.length, 2); // expected-not-found + decoded-not-expected

    // Tampered recipient.
    const wrongRecipient = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: Keypair.generate().publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(wrongRecipient.ok, false);

    // Extra decoded recipient (expected list empty).
    const extraDecoded = compareDecodedToExpected(decoded, {
      recipients: [],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(extraDecoded.ok, false);
    assert.ok(
      extraDecoded.mismatches.some((m) =>
        m.includes("not present in the expected payload")
      )
    );

    // Non-integer expected amount fails closed.
    const badAmount = compareDecodedToExpected(decoded, {
      recipients: [
        { address: recipientOwner.publicKey.toBase58(), amount: "1.5" },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(badAmount.ok, false);
  });

  it("(f2) reports a mint mismatch for SPL transfers", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: [
        splTransferCheckedInstruction(),
        feeReimburseInstruction(),
      ],
    });
    const destAta = deriveAssociatedTokenAddress(
      recipientOwner.publicKey,
      mint
    ).toBase58();
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    const compared = compareDecodedToExpected(decoded, {
      recipients: [{ address: destAta, amount: SPL_AMOUNT.toString() }],
      tokenMint: Keypair.generate().publicKey.toBase58(),
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
    assert.ok(
      compared.mismatches.some((m) =>
        m.includes("does not match expected mint")
      )
    );
  });

  it("(g) returns undecodable for garbage, truncated and empty inputs", async function () {
    const garbage = decodeVaultSolanaTransaction(
      "!!!this is not a transaction!!!",
      PROGRAM_ID
    );
    assert.equal(garbage.kind, "undecodable");
    if (garbage.kind === "undecodable") {
      assert.ok(garbage.error.length > 0);
    }

    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
    });
    const bytes = Buffer.from(base64, "base64");
    const truncated = decodeVaultSolanaTransaction(
      bytes.subarray(0, Math.floor(bytes.length / 2)).toString("base64"),
      PROGRAM_ID
    );
    assert.equal(truncated.kind, "undecodable");

    const empty = decodeVaultSolanaTransaction("", PROGRAM_ID);
    assert.equal(empty.kind, "undecodable");

    // compareDecodedToExpected on undecodable is never ok.
    const compared = compareDecodedToExpected(garbage, { recipients: [] });
    assert.equal(compared.ok, false);
  });

  it("(g2) returns undecodable when no multisig instruction is present", async function () {
    const nonceAccount = await deriveNonceAccount(multisigAddress);
    const tx = new Transaction().add(
      SystemProgram.nonceAdvance({
        noncePubkey: nonceAccount,
        authorizedPubkey: paymaster.publicKey,
      })
    );
    tx.recentBlockhash = Keypair.generate().publicKey.toBase58();
    tx.feePayer = paymaster.publicKey;
    const base64 = tx
      .serialize({ requireAllSignatures: false, verifySignatures: false })
      .toString("base64");
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "undecodable");
  });

  it("(h) counts unknown inner instructions and fails the comparison", async function () {
    const foreignProgram = Keypair.generate().publicKey;
    const unknownInnerIx = new TransactionInstruction({
      programId: foreignProgram,
      keys: [{ pubkey: vaultPda, isSigner: true, isWritable: true }],
      data: Buffer.from("arbitrary"),
    });
    const { base64 } = await buildBundle({
      innerInstructions: [...nativeInnerInstructions(), unknownInnerIx],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.unknownInnerInstructionCount, 1);
    // The known transfers still decode.
    assert.equal(decoded.recipients.length, 1);
    assert.equal(decoded.feeLamports, FEE_LAMPORTS.toString());

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
    assert.ok(
      compared.mismatches.some((m) =>
        m.includes("unrecognized inner instruction")
      )
    );
  });

  it("decodes with Token-2022 as the inner token program", async function () {
    const sourceAta = deriveAssociatedTokenAddress(
      vaultPda,
      mint,
      TOKEN_2022_PROGRAM_ID
    );
    const destAta = deriveAssociatedTokenAddress(
      recipientOwner.publicKey,
      mint,
      TOKEN_2022_PROGRAM_ID
    );
    const data = Buffer.alloc(10);
    data[0] = 12;
    data.writeBigUInt64LE(SPL_AMOUNT, 1);
    data[9] = DECIMALS;
    const ix = new TransactionInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      keys: [
        { pubkey: sourceAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: destAta, isSigner: false, isWritable: true },
        { pubkey: vaultPda, isSigner: true, isWritable: false },
      ],
      data,
    });
    const { base64 } = await buildBundle({
      innerInstructions: [ix, feeReimburseInstruction()],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID, {
      expectedRecipientOwner: recipientOwner.publicKey.toBase58(),
      expectedMint: mint.toBase58(),
    });
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients.length, 1);
    // Token-2022 ATA derivation candidate matches -> owner-resolved.
    assert.equal(decoded.recipients[0].ataVerified, true);
    assert.equal(
      decoded.recipients[0].address,
      recipientOwner.publicKey.toBase58()
    );
  });

  // ---- Regression tests for the 2026-07 SDK audit fixes ----

  it("(fix-crit) rejects a vault->fee-payer drain smuggled as an unbounded fee", async function () {
    const DRAIN = BigInt(99_000_000);
    const { base64 } = await buildBundle({
      innerInstructions: [
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: recipientOwner.publicKey,
          lamports: NATIVE_AMOUNT,
        }),
        // Hidden drain: vault -> fee payer for (almost) the whole balance.
        SystemProgram.transfer({
          fromPubkey: vaultPda,
          toPubkey: paymaster.publicKey,
          lamports: DRAIN,
        }),
      ],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    // The drain is bucketed as fee and excluded from recipients...
    assert.equal(decoded.recipients.length, 1);
    assert.equal(decoded.feeLamports, DRAIN.toString());

    const expected = {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
    };

    // ...but with a sane fee cap the gate now REJECTS it (the old code passed).
    const capped = compareDecodedToExpected(decoded, {
      ...expected,
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(capped.ok, false);
    assert.ok(
      capped.mismatches.some((m) => m.includes("exceeds the allowed maximum"))
    );

    // Default (no cap) is fail-closed: any fee rejects.
    const defaulted = compareDecodedToExpected(decoded, expected);
    assert.equal(defaulted.ok, false);

    // Only an explicit cap >= the drain allows it (caller's eyes open).
    const allowed = compareDecodedToExpected(decoded, {
      ...expected,
      maxFeeLamports: DRAIN.toString(),
    });
    assert.equal(allowed.ok, true);
  });

  it("(fix-crit2) rejects a fee paid to an unexpected fee payer", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.feePayer, paymaster.publicKey.toBase58());

    const base = {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    };
    const wrongPayer = compareDecodedToExpected(decoded, {
      ...base,
      expectedFeePayer: Keypair.generate().publicKey.toBase58(),
    });
    assert.equal(wrongPayer.ok, false);
    assert.ok(
      wrongPayer.mismatches.some((m) => m.includes("expected fee payer"))
    );

    const rightPayer = compareDecodedToExpected(decoded, {
      ...base,
      expectedFeePayer: paymaster.publicKey.toBase58(),
    });
    assert.equal(rightPayer.ok, true);
  });

  it("(fix-med) rejects a bundle whose approve targets a different proposal", async function () {
    const bogusProposal = Keypair.generate().publicKey;
    const { base64, transactionAddress } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
      approveTargetOverride: bogusProposal,
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    // The created proposal is transactionAddress, but the approves point elsewhere.
    assert.equal(decoded.transactionPda, transactionAddress.toBase58());
    assert.ok(
      decoded.approveTargets.every((t) => t === bogusProposal.toBase58())
    );

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
    assert.ok(
      compared.mismatches.some((m) => m.includes("not the created proposal"))
    );
  });

  it("(fix-med2) binds the created proposal to expectedTransactionPda", async function () {
    const { base64, transactionAddress } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    const base = {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    };
    const wrong = compareDecodedToExpected(decoded, {
      ...base,
      expectedTransactionPda: Keypair.generate().publicKey.toBase58(),
    });
    assert.equal(wrong.ok, false);
    assert.ok(
      wrong.mismatches.some((m) => m.includes("does not match expected"))
    );

    const right = compareDecodedToExpected(decoded, {
      ...base,
      expectedTransactionPda: transactionAddress.toBase58(),
    });
    assert.equal(right.ok, true);
  });

  it("(fix-info) flags an ATA-create funded by a non-fee-payer", async function () {
    const { base64 } = await buildBundle({
      innerInstructions: nativeInnerInstructions(),
      includeAtaCreate: true,
      ataFunder: walletMember.publicKey, // a member leaf, not the paymaster
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.deepEqual(decoded.unknownOuterPrograms, [ATA_PROGRAM_ID.toBase58()]);

    const compared = compareDecodedToExpected(decoded, {
      recipients: [
        {
          address: recipientOwner.publicKey.toBase58(),
          amount: NATIVE_AMOUNT.toString(),
        },
      ],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
  });

  it("(fix-spl-auth) flags an SPL transfer not authorized by the vault", async function () {
    const memberAta = deriveAssociatedTokenAddress(
      walletMember.publicKey,
      mint
    );
    const destAta = deriveAssociatedTokenAddress(
      recipientOwner.publicKey,
      mint
    );
    const data = Buffer.alloc(10);
    data[0] = 12; // TransferChecked
    data.writeBigUInt64LE(SPL_AMOUNT, 1);
    data[9] = DECIMALS;
    // Authority is a MEMBER leaf, not the vault -> the debit is not from the
    // vault, so it must be flagged (fail-closed) rather than shown as a vault
    // recipient — mirrors the native source==vault guard.
    const badAuthIx = new TransactionInstruction({
      programId: TOKEN_PROGRAM_ID,
      keys: [
        { pubkey: memberAta, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: destAta, isSigner: false, isWritable: true },
        { pubkey: walletMember.publicKey, isSigner: true, isWritable: false },
      ],
      data,
    });
    const { base64 } = await buildBundle({
      innerInstructions: [badAuthIx, feeReimburseInstruction()],
    });
    const decoded = decodeVaultSolanaTransaction(base64, PROGRAM_ID);
    assert.equal(decoded.kind, "create");
    if (decoded.kind !== "create") return;
    assert.equal(decoded.recipients.length, 0);
    assert.equal(decoded.unknownInnerInstructionCount, 1);

    const compared = compareDecodedToExpected(decoded, {
      recipients: [],
      maxFeeLamports: FEE_LAMPORTS.toString(),
    });
    assert.equal(compared.ok, false);
    assert.ok(
      compared.mismatches.some((m) =>
        m.includes("unrecognized inner instruction")
      )
    );
  });
});
