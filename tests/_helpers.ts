import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  AddressLookupTableProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as crypto from "crypto";
import * as nacl from "tweetnacl";
import type { SolanaMultisig } from "../target/types/solana_multisig";

/** Sort pubkeys by raw bytes — must match the program's `sort_members`. */
export function sortMembers(members: PublicKey[]): PublicKey[] {
  return [...members].sort((a, b) =>
    Buffer.compare(a.toBuffer(), b.toBuffer())
  );
}

/** sha256 of concatenated raw pubkey bytes — must match `hash_members`. */
export function hashMembers(members: PublicKey[]): Buffer {
  const h = crypto.createHash("sha256");
  for (const m of members) h.update(m.toBytes());
  return h.digest();
}

/**
 * Init message: prefix (20) || sha256(sorted_members) (32) || threshold (1)
 * = 53 bytes regardless of member count.
 */
export function buildInitMessage(
  members: PublicKey[],
  threshold: number
): Buffer {
  return Buffer.concat([
    Buffer.from("SOLANA_MULTISIG_INIT"),
    hashMembers(sortMembers(members)),
    Buffer.from([threshold]),
  ]);
}

export interface InitSignature {
  signer: PublicKey;
  signature: number[];
}

/** Each member produces one Ed25519 signature over the init message. */
export function signInitMessage(
  members: PublicKey[],
  threshold: number,
  signer: Keypair
): InitSignature {
  const message = buildInitMessage(members, threshold);
  const signature = nacl.sign.detached(message, signer.secretKey);
  return { signer: signer.publicKey, signature: Array.from(signature) };
}

const ED25519_PROGRAM_ID = new PublicKey(
  "Ed25519SigVerify111111111111111111111111111"
);

/**
 * Pack signature pairs into a SINGLE Ed25519 native-program instruction.
 * Layout matches the program's `verify_ed25519_batch` parser.
 */
export function makeBatchedEd25519Ix(
  sigs: Array<{ signer: PublicKey; signature: number[] | Uint8Array }>,
  message: Buffer
): TransactionInstruction {
  const n = sigs.length;
  const headerSize = 2 + 14 * n;
  const sigsStart = headerSize;
  const pubkeysStart = sigsStart + n * 64;
  const messageStart = pubkeysStart + n * 32;
  const data = Buffer.alloc(messageStart + message.length);

  data.writeUInt8(n, 0);
  data.writeUInt8(0, 1);
  for (let i = 0; i < n; i++) {
    const entry = 2 + i * 14;
    const sigOffset = sigsStart + i * 64;
    const pubkeyOffset = pubkeysStart + i * 32;
    data.writeUInt16LE(sigOffset, entry);
    data.writeUInt16LE(0xffff, entry + 2);
    data.writeUInt16LE(pubkeyOffset, entry + 4);
    data.writeUInt16LE(0xffff, entry + 6);
    data.writeUInt16LE(messageStart, entry + 8);
    data.writeUInt16LE(message.length, entry + 10);
    data.writeUInt16LE(0xffff, entry + 12);
    Buffer.from(sigs[i].signature).copy(data, sigOffset);
    Buffer.from(sigs[i].signer.toBytes()).copy(data, pubkeyOffset);
  }
  message.copy(data, messageStart);

  return new TransactionInstruction({
    keys: [],
    programId: ED25519_PROGRAM_ID,
    data,
  });
}

/**
 * Create an Address Lookup Table populated with `members` PLUS the well-
 * known accounts the init ix references (`SystemProgram`, instructions
 * sysvar). Including those system accounts in the ALT lets the V0 compiler
 * route them through the ALT lookup instead of repeating their 32-byte
 * pubkeys in the static account list — recovers ~64 bytes that's needed
 * to fit big multisigs (e.g. 7-of-10) under the 1232-byte tx cap.
 *
 * Waits for (a) the 1-slot warm-up Solana requires before a fresh ALT is
 * referenceable from a V0 tx, and (b) the ALT account to actually report
 * the expected number of addresses (otherwise the V0 compiler doesn't
 * find them and falls back to static keys).
 */
export async function createMembersAlt(
  connection: Connection,
  payer: Keypair,
  members: PublicKey[]
): Promise<PublicKey> {
  const sorted = sortMembers(members);
  // Include system accounts referenced by the init ix so the V0 compiler
  // routes them through the ALT instead of bloating the static account list.
  const altAddresses = [
    ...sorted,
    SystemProgram.programId,
    anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
  ];

  const recentSlot = await connection.getSlot("finalized");
  const [createIx, lookupTableAddress] =
    AddressLookupTableProgram.createLookupTable({
      authority: payer.publicKey,
      payer: payer.publicKey,
      recentSlot,
    });
  const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer: payer.publicKey,
    authority: payer.publicKey,
    lookupTable: lookupTableAddress,
    addresses: altAddresses,
  });

  const tx = new anchor.web3.Transaction().add(createIx, extendIx);
  await anchor.web3.sendAndConfirmTransaction(connection, tx, [payer], {
    commitment: "confirmed",
  });

  // 1-slot warm-up + poll until the ALT account reports all addresses.
  const startSlot = await connection.getSlot("processed");
  while ((await connection.getSlot("processed")) <= startSlot + 1) {
    await new Promise((r) => setTimeout(r, 200));
  }

  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const acc = await connection.getAddressLookupTable(lookupTableAddress);
    if (acc.value && acc.value.state.addresses.length === altAddresses.length) {
      return lookupTableAddress;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(
    `ALT ${lookupTableAddress.toBase58()} did not finalize ${
      altAddresses.length
    } addresses within 10s`
  );
}

/**
 * Build + send the init transaction.
 *
 *   ix[0] = batched Ed25519 ix verifying every signature in `sigs`
 *   ix[1] = `initialize_multisig(member_hash, threshold)` with members
 *           passed via `remaining_accounts`
 *
 * If `alt` is provided, sends a V0 tx with that ALT lookup so members
 * cost ~1 byte each (fits up to ~7 raw signatures under the 1232-byte
 * cap, regardless of N). Without `alt`, sends a legacy tx with members
 * in the static account list — faster (no ALT setup latency) but only
 * fits ~5-6 members.
 */
export async function sendInitTxViaAlt(opts: {
  program: Program<SolanaMultisig>;
  connection: Connection;
  multisig: PublicKey;
  members: PublicKey[];
  threshold: number;
  sigs: InitSignature[];
  payer: Keypair;
  alt?: PublicKey;
}): Promise<string> {
  const sortedMembers = sortMembers(opts.members);
  const memberHash = hashMembers(sortedMembers);

  const message = buildInitMessage(opts.members, opts.threshold);
  const ed25519Ix = makeBatchedEd25519Ix(opts.sigs, message);

  const initIx = await opts.program.methods
    .initializeMultisig(Array.from(memberHash), opts.threshold)
    .accountsPartial({
      multisig: opts.multisig,
      payer: opts.payer.publicKey,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(
      sortedMembers.map((pubkey) => ({
        pubkey,
        isSigner: false,
        isWritable: false,
      }))
    )
    .instruction();

  if (opts.alt) {
    const altResp = await opts.connection.getAddressLookupTable(opts.alt);
    if (!altResp.value) throw new Error(`ALT ${opts.alt.toBase58()} not found`);

    const { blockhash } = await opts.connection.getLatestBlockhash();
    const v0Message = new TransactionMessage({
      payerKey: opts.payer.publicKey,
      recentBlockhash: blockhash,
      instructions: [ed25519Ix, initIx],
    }).compileToV0Message([altResp.value]);

    const tx = new VersionedTransaction(v0Message);
    tx.sign([opts.payer]);
    const sig = await opts.connection.sendTransaction(tx);
    await opts.connection.confirmTransaction(sig, "confirmed");
    return sig;
  }

  // No ALT: send as a legacy tx with members in the static account list.
  const legacyTx = new anchor.web3.Transaction().add(ed25519Ix, initIx);
  return anchor.web3.sendAndConfirmTransaction(
    opts.connection,
    legacyTx,
    [opts.payer],
    { commitment: "confirmed" }
  );
}

/**
 * Convenience: end-to-end "give me a working multisig". Funds members,
 * collects threshold signatures, and submits the init tx.
 *
 * For multisigs with `members.length <= 5` we skip ALT setup entirely
 * (faster). Larger multisigs auto-create an ALT to stay within Solana's
 * 1232-byte tx cap. Pass `useAlt: true` to force the ALT path.
 */
export async function setupMultisigViaAlt(opts: {
  program: Program<SolanaMultisig>;
  connection: Connection;
  members: Keypair[];
  threshold: number;
  payer?: Keypair;
  useAlt?: boolean;
}): Promise<{ multisig: PublicKey; alt: PublicKey | null; payer: Keypair }> {
  const payer = opts.payer ?? opts.members[0];
  const memberKeys = opts.members.map((m) => m.publicKey);
  const sortedKeys = sortMembers(memberKeys);

  const multisig: PublicKey = (await opts.program.methods
    .deriveAddress(sortedKeys, opts.threshold)
    .view()) as PublicKey;

  const needsAlt = opts.useAlt || memberKeys.length > 5;
  const alt = needsAlt
    ? await createMembersAlt(opts.connection, payer, sortedKeys)
    : null;

  const sigs = opts.members
    .slice(0, opts.threshold)
    .map((m) => signInitMessage(memberKeys, opts.threshold, m));

  await sendInitTxViaAlt({
    program: opts.program,
    connection: opts.connection,
    multisig,
    members: memberKeys,
    threshold: opts.threshold,
    sigs,
    payer,
    alt: alt ?? undefined,
  });

  return { multisig, alt, payer };
}
