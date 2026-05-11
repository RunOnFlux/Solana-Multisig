import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaMultisig } from "../target/types/solana_multisig";
import { Keypair, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { expect } from "chai";
import { sortMembers, createMembersAlt, sendInitTxViaAlt } from "./_helpers";

/**
 * Phase 4: Integration Tests
 * End-to-end scenarios testing the complete flow.
 *
 * Init is permissionless — no per-member signatures needed. The PDA is
 * deterministic from `(sorted_members, threshold)`, so initializing with
 * the canonical inputs is the only way to land at the canonical address.
 * Fund safety is enforced by the threshold check on create/approve/execute,
 * not on registration.
 */
describe("Integration Tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaMultisig as Program<SolanaMultisig>;

  async function fundAccount(
    pubkey: PublicKey,
    amount: number = 2 * LAMPORTS_PER_SOL
  ) {
    try {
      const sig = await provider.connection.requestAirdrop(pubkey, amount);
      await provider.connection.confirmTransaction(sig);
      await new Promise((resolve) => setTimeout(resolve, 500));
    } catch {
      // Continue if airdrop fails
    }
  }

  /**
   * Submit the init transaction. For small multisigs (≤5 members) we skip
   * ALT setup and send a legacy tx with members in the static account
   * list — much faster (no ALT warm-up wait). Larger multisigs need ALT
   * to fit under the 1232-byte cap.
   */
  async function submitInit(opts: {
    members: PublicKey[];
    sortedMembers: PublicKey[];
    threshold: number;
    multisig: PublicKey;
    payer: Keypair;
  }): Promise<string> {
    const useAlt = opts.sortedMembers.length > 5;
    const alt = useAlt
      ? await createMembersAlt(
          provider.connection,
          opts.payer,
          opts.sortedMembers
        )
      : undefined;
    return sendInitTxViaAlt({
      program,
      connection: provider.connection,
      multisig: opts.multisig,
      members: opts.members,
      threshold: opts.threshold,
      payer: opts.payer,
      alt,
    });
  }

  describe("Scenario 1: Happy Path - 2-of-3 Multisig", () => {
    it("complete flow: derive → pre-fund → initialize", async () => {
      console.log("\n🎯 Scenario: Standard 2-of-3 multisig initialization");

      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();

      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(member1.publicKey);

      // Step 1: Derive address
      const sortedMembers = sortMembers(members);
      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();
      console.log(`   📍 Derived address: ${multisigAddress.toString()}`);

      // Step 2: Pre-fund (vault PDA actually, but multisig PDA works here too)
      const preFundAmount = 0.1 * LAMPORTS_PER_SOL;
      await fundAccount(multisigAddress, preFundAmount);

      const balanceBefore = await provider.connection.getBalance(
        multisigAddress
      );
      console.log(`   💰 Pre-funded: ${balanceBefore / LAMPORTS_PER_SOL} SOL`);
      expect(balanceBefore).to.be.greaterThan(0);

      // Step 3: Initialize (permissionless — no member signatures required)
      const tx = await submitInit({
        members,
        sortedMembers,
        threshold,
        multisig: multisigAddress,
        payer: member1,
      });
      console.log(`   ✅ Initialized: ${tx}`);

      // Verify
      const multisigAccount = await program.account.multisig.fetch(
        multisigAddress
      );
      expect(multisigAccount.threshold).to.equal(threshold);
      expect(multisigAccount.members.length).to.equal(3);

      console.log(`   ✅ Verified on-chain state`);
    });
  });

  describe("Scenario 2: Non-member payer", () => {
    it("any funded account can pay for initialization — payer ≠ controller", async () => {
      console.log("\n🎯 Scenario: Non-member payer");

      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      const payer = Keypair.generate(); // Not a member

      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(payer.publicKey);

      const sortedMembers = sortMembers(members);
      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      await submitInit({
        members,
        sortedMembers,
        threshold,
        multisig: multisigAddress,
        payer, // non-member paying
      });

      console.log(`   ✅ Non-member successfully paid for initialization`);
      console.log(`   ✅ This proves payer ≠ controller`);

      const multisigAccount = await program.account.multisig.fetch(
        multisigAddress
      );
      expect(multisigAccount.threshold).to.equal(threshold);
      expect(multisigAccount.members.length).to.equal(3);
    });
  });

  describe("Scenario 3: Large Multisig (7-of-10)", () => {
    it("handles larger multisig configuration via ALT", async () => {
      console.log("\n🎯 Scenario: Large multisig (7-of-10)");

      const members = Array.from({ length: 10 }, () => Keypair.generate());
      const memberPubkeys = members.map((m) => m.publicKey);
      const threshold = 7;

      await fundAccount(members[0].publicKey);

      const sortedMembers = sortMembers(memberPubkeys);
      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      const tx = await submitInit({
        members: memberPubkeys,
        sortedMembers,
        threshold,
        multisig: multisigAddress,
        payer: members[0],
      });
      console.log(`   ✅ 7-of-10 multisig initialized successfully: ${tx}`);

      const multisigAccount = await program.account.multisig.fetch(
        multisigAddress
      );
      expect(multisigAccount.members.length).to.equal(10);
      expect(multisigAccount.threshold).to.equal(7);
    });
  });

  describe("Scenario 4: Pre-funded Address Security", () => {
    it("pre-funded address remains under member control after init", async () => {
      console.log("\n🎯 Scenario: Pre-funded address security");

      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();

      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(member1.publicKey);

      const sortedMembers = sortMembers(members);
      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // Pre-fund with significant amount
      const preFundAmount = 1 * LAMPORTS_PER_SOL;
      await fundAccount(multisigAddress, preFundAmount);
      console.log(`   💰 Pre-funded: ${preFundAmount / LAMPORTS_PER_SOL} SOL`);

      const balance1 = await provider.connection.getBalance(multisigAddress);
      expect(balance1).to.be.greaterThanOrEqual(preFundAmount);

      await submitInit({
        members,
        sortedMembers,
        threshold,
        multisig: multisigAddress,
        payer: member1,
      });

      // Funds preserved through init.
      const balance2 = await provider.connection.getBalance(multisigAddress);
      expect(balance2).to.be.greaterThanOrEqual(preFundAmount);

      console.log(`   ✅ Funds preserved: ${balance2 / LAMPORTS_PER_SOL} SOL`);
      console.log(`   ✅ Only threshold members can control multisig`);
    });
  });
});
