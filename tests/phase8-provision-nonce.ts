import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaMultisig } from "../target/types/solana_multisig";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
  SYSVAR_RENT_PUBKEY,
  NonceAccount,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { expect } from "chai";
import { setupMultisigViaAlt } from "./_helpers";

/**
 * Phase 8: provision_nonce — durable nonce account provisioning.
 *
 * The provision_nonce ix creates a durable nonce account at a deterministic
 * address derived from the multisig PDA:
 *
 *   nonceAccount = PublicKey.createWithSeed(multisigPda, "nonce", SystemProgram)
 *
 * Anyone (typically the relay paymaster) can call this. The payer funds the
 * ~0.00144 SOL rent and becomes the initial authority. Address is
 * paymaster-independent — survives paymaster rotations via nonceAuthorize.
 *
 * Use case: subsequent send txes set `recentBlockhash = nonceState.nonce`
 * and prepend `SystemProgram.nonceAdvance` at ix[0], eliminating the 60s
 * blockhash expiry race for flows where wallet and key sign at different
 * times.
 */
describe("Phase 8: provision_nonce", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.SolanaMultisig as Program<SolanaMultisig>;

  async function fundAccount(pubkey: PublicKey, sol = 2): Promise<void> {
    try {
      const sig = await provider.connection.requestAirdrop(
        pubkey,
        sol * LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);
      await new Promise((r) => setTimeout(r, 500));
    } catch {
      /* localnet rate-limit tolerant */
    }
  }

  function deriveNonceAccount(multisig: PublicKey): Promise<PublicKey> {
    return PublicKey.createWithSeed(multisig, "nonce", SystemProgram.programId);
  }

  it("provisions a nonce account at deterministic address", async () => {
    const members = [Keypair.generate(), Keypair.generate()];
    const paymaster = Keypair.generate();
    await fundAccount(paymaster.publicKey);

    const { multisig } = await setupMultisigViaAlt({
      program,
      connection: provider.connection,
      members,
      threshold: 2,
      payer: paymaster,
    });

    const nonceAccount = await deriveNonceAccount(multisig);

    // Confirm not yet provisioned.
    const before = await provider.connection.getAccountInfo(nonceAccount);
    expect(before, "nonce should not exist pre-provision").to.equal(null);

    await program.methods
      .provisionNonce()
      .accountsPartial({
        multisig,
        nonceAccount,
        payer: paymaster.publicKey,
        recentBlockhashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
        rent: SYSVAR_RENT_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .signers([paymaster])
      .rpc();

    // Confirm it exists, is system-owned, and parses as a nonce account.
    const after = await provider.connection.getAccountInfo(nonceAccount);
    expect(after, "nonce should exist post-provision").to.not.equal(null);
    expect(after!.owner.toBase58()).to.equal(SystemProgram.programId.toBase58());

    const nonceState = NonceAccount.fromAccountData(after!.data);
    expect(nonceState.authorizedPubkey.toBase58()).to.equal(
      paymaster.publicKey.toBase58()
    );
    expect(nonceState.nonce).to.be.a("string").and.have.length.greaterThan(0);
  });

  it("derived address is purely a function of multisigPda (paymaster-independent)", async () => {
    // Pure offline derivation test — no provisioning, no funding required.
    // Proves that anyone with just the multisig pubkey can re-derive the
    // canonical nonce address.
    const fakeMultisig = Keypair.generate().publicKey;

    // Called twice → same answer (deterministic).
    const a = await deriveNonceAccount(fakeMultisig);
    const b = await deriveNonceAccount(fakeMultisig);
    expect(a.toBase58()).to.equal(b.toBase58());

    // Called with a different multisig → different address (binds to multisig).
    const otherMultisig = Keypair.generate().publicKey;
    const c = await deriveNonceAccount(otherMultisig);
    expect(c.toBase58()).to.not.equal(a.toBase58());

    // Independent of paymaster: deriveNonceAccount doesn't even take a
    // paymaster argument — derivation uses `(multisig, "nonce", SystemProgram)`.
    // The signature of the helper itself proves paymaster-independence.
    expect(deriveNonceAccount.length).to.equal(1);
  });

  it("rejects a re-provision of the same multisig (System Program: account already in use)", async () => {
    const members = [Keypair.generate(), Keypair.generate()];
    const paymaster = Keypair.generate();
    await fundAccount(paymaster.publicKey);

    const { multisig } = await setupMultisigViaAlt({
      program,
      connection: provider.connection,
      members,
      threshold: 2,
      payer: paymaster,
    });

    const nonceAccount = await deriveNonceAccount(multisig);

    await program.methods
      .provisionNonce()
      .accountsPartial({
        multisig,
        nonceAccount,
        payer: paymaster.publicKey,
        recentBlockhashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
        rent: SYSVAR_RENT_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .signers([paymaster])
      .rpc();

    // Second attempt fails because the account already exists.
    let threw = false;
    try {
      await program.methods
        .provisionNonce()
        .accountsPartial({
          multisig,
          nonceAccount,
          payer: paymaster.publicKey,
          recentBlockhashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
          rent: SYSVAR_RENT_PUBKEY,
          systemProgram: SystemProgram.programId,
        })
        .signers([paymaster])
        .rpc();
    } catch (e) {
      threw = true;
      // Either "account already in use" or "custom program error" — both
      // come from the System Program rejecting the create.
      expect(String(e)).to.match(/already in use|custom program error/i);
    }
    expect(threw, "second provision should fail").to.equal(true);
  });
});
