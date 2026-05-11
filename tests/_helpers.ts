import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  AddressLookupTableProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as crypto from "crypto";
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
 * Create an Address Lookup Table populated with `members` PLUS
 * `SystemProgram` (which the init ix references). Including SystemProgram
 * in the ALT lets the V0 compiler route it through the ALT lookup instead
 * of bloating the static account list.
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
  // Include SystemProgram (referenced by the init ix) so the V0 compiler
  // routes it through the ALT instead of bloating the static account list.
  const altAddresses = [...sorted, SystemProgram.programId];

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
 * Build + send the init transaction. Permissionless — only one ix:
 *
 *   ix[0] = `initialize_multisig(member_hash, threshold, member_count)`
 *           with members passed via `remaining_accounts`
 *
 * No member signatures are required. The payer (any signer) covers rent.
 * If `alt` is provided, sends a V0 tx with that ALT lookup so members
 * cost ~1 byte each. Without `alt`, sends a legacy tx with members in
 * the static account list.
 */
export async function sendInitTxViaAlt(opts: {
  program: Program<SolanaMultisig>;
  connection: Connection;
  multisig: PublicKey;
  members: PublicKey[];
  threshold: number;
  payer: Keypair;
  alt?: PublicKey;
}): Promise<string> {
  const sortedMembers = sortMembers(opts.members);
  const memberHash = hashMembers(sortedMembers);

  const initIx = await opts.program.methods
    .initializeMultisig(
      Array.from(memberHash),
      opts.threshold,
      sortedMembers.length
    )
    .accountsPartial({
      multisig: opts.multisig,
      payer: opts.payer.publicKey,
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
      instructions: [initIx],
    }).compileToV0Message([altResp.value]);

    const tx = new VersionedTransaction(v0Message);
    tx.sign([opts.payer]);
    const sig = await opts.connection.sendTransaction(tx);
    await opts.connection.confirmTransaction(sig, "confirmed");
    return sig;
  }

  // No ALT: send as a legacy tx with members in the static account list.
  const legacyTx = new anchor.web3.Transaction().add(initIx);
  return anchor.web3.sendAndConfirmTransaction(
    opts.connection,
    legacyTx,
    [opts.payer],
    { commitment: "confirmed" }
  );
}

/**
 * Convenience: end-to-end "give me a working multisig". Init is
 * permissionless (no member sigs needed); we only need a payer for rent.
 *
 * For multisigs with `members.length <= 5` we skip ALT setup (faster).
 * Larger multisigs auto-create an ALT to stay within Solana's 1232-byte
 * tx cap. Pass `useAlt: true` to force the ALT path.
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

  await sendInitTxViaAlt({
    program: opts.program,
    connection: opts.connection,
    multisig,
    members: memberKeys,
    threshold: opts.threshold,
    payer,
    alt: alt ?? undefined,
  });

  return { multisig, alt, payer };
}
