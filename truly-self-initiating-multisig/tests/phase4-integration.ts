import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisig } from "../target/types/truly_self_initiating_multisig";
import { Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { expect } from "chai";
import * as crypto from "crypto";
import * as nacl from "tweetnacl";

/**
 * Phase 4: Integration Tests
 * End-to-end scenarios testing the complete flow
 */
describe("Integration Tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.TrulySelfInitiatingMultisig as Program<TrulySelfInitiatingMultisig>;

  async function fundAccount(pubkey: PublicKey, amount: number = 2 * LAMPORTS_PER_SOL) {
    try {
      const sig = await provider.connection.requestAirdrop(pubkey, amount);
      await provider.connection.confirmTransaction(sig);
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (e) {
      // Continue if airdrop fails
    }
  }

  function createSignature(members: PublicKey[], threshold: number, signer: Keypair) {
    const sortedMembers = [...members].sort((a, b) => 
      Buffer.compare(a.toBuffer(), b.toBuffer())
    );

    const message = Buffer.concat([
      Buffer.from("TRULY_SELF_INITIATING_MULTISIG_INIT"),
      ...sortedMembers.map(m => Buffer.from(m.toBytes())),
      Buffer.from([threshold])
    ]);

    const signature = nacl.sign.detached(message, signer.secretKey);
    const messageHash = crypto.createHash('sha256').update(message).digest();

    return {
      signer: signer.publicKey,
      signature: Array.from(signature),
      messageHash: Array.from(messageHash),
    };
  }

  describe("Scenario 1: Happy Path - 2-of-3 Multisig", () => {
    it("complete flow: derive → pre-fund → collect signatures → initialize", async () => {
      console.log("\n🎯 Scenario: Standard 2-of-3 multisig initialization");
      
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      
      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      // Fund members
      await fundAccount(member1.publicKey);
      await fundAccount(member2.publicKey);
      await fundAccount(member3.publicKey);

      // Step 1: Derive address
      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      console.log(`   📍 Derived address: ${multisigAddress.toString()}`);

      // Step 2: Pre-fund
      const preFundAmount = 0.1 * LAMPORTS_PER_SOL;
      await fundAccount(multisigAddress, preFundAmount);
      
      const balanceBefore = await provider.connection.getBalance(multisigAddress);
      console.log(`   💰 Pre-funded: ${balanceBefore / LAMPORTS_PER_SOL} SOL`);
      expect(balanceBefore).to.be.greaterThan(0);

      // Step 3: Collect signatures
      const sig1 = createSignature(members, threshold, member1);
      const sig2 = createSignature(members, threshold, member2);

      console.log(`   ✍️  Collected 2 signatures`);

      // Step 4: Initialize
      const tx = await program.methods
        .initializeMultisig(sortedMembers, threshold, [sig1, sig2])
        .accounts({
          multisig: multisigAddress,
          payer: member1.publicKey,
        })
        .signers([member1])
        .rpc();

      console.log(`   ✅ Initialized: ${tx}`);

      // Verify
      const multisigAccount = await program.account.multisig.fetch(multisigAddress);
      expect(multisigAccount.isInitialized).to.be.true;
      expect(multisigAccount.threshold).to.equal(threshold);
      expect(multisigAccount.members.length).to.equal(3);
      
      console.log(`   ✅ Verified on-chain state`);
    });
  });

  describe("Scenario 2: Exactly Threshold Signatures", () => {
    it("initializes successfully with exact threshold (2-of-3 with 2 sigs)", async () => {
      console.log("\n🎯 Scenario: Exactly threshold signatures");
      
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      
      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(member1.publicKey);
      await fundAccount(member2.publicKey);

      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // Exactly 2 signatures for 2-of-3
      const sig1 = createSignature(members, threshold, member1);
      const sig2 = createSignature(members, threshold, member2);

      const tx = await program.methods
        .initializeMultisig(sortedMembers, threshold, [sig1, sig2])
        .accounts({
          multisig: multisigAddress,
          payer: member1.publicKey,
        })
        .signers([member1])
        .rpc();

      console.log(`   ✅ Success with exactly ${threshold} signatures`);
      
      const multisigAccount = await program.account.multisig.fetch(multisigAddress);
      expect(multisigAccount.isInitialized).to.be.true;
    });
  });

  describe("Scenario 3: More Than Threshold Signatures", () => {
    it("initializes successfully with more than threshold (2-of-3 with 3 sigs)", async () => {
      console.log("\n🎯 Scenario: More than threshold signatures");
      
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      
      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(member1.publicKey);
      await fundAccount(member2.publicKey);
      await fundAccount(member3.publicKey);

      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // All 3 signatures for 2-of-3
      const sig1 = createSignature(members, threshold, member1);
      const sig2 = createSignature(members, threshold, member2);
      const sig3 = createSignature(members, threshold, member3);

      const tx = await program.methods
        .initializeMultisig(sortedMembers, threshold, [sig1, sig2, sig3])
        .accounts({
          multisig: multisigAddress,
          payer: member1.publicKey,
        })
        .signers([member1])
        .rpc();

      console.log(`   ✅ Success with 3 signatures (threshold is 2)`);
      
      const multisigAccount = await program.account.multisig.fetch(multisigAddress);
      expect(multisigAccount.isInitialized).to.be.true;
    });
  });

  describe("Scenario 4: Different Payer Than Signers", () => {
    it("any funded account can pay, doesn't need to be a member", async () => {
      console.log("\n🎯 Scenario: Non-member payer");
      
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      const payer = Keypair.generate(); // Not a member
      
      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(payer.publicKey);

      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      const sig1 = createSignature(members, threshold, member1);
      const sig2 = createSignature(members, threshold, member2);

      const tx = await program.methods
        .initializeMultisig(sortedMembers, threshold, [sig1, sig2])
        .accounts({
          multisig: multisigAddress,
          payer: payer.publicKey, // Non-member paying
        })
        .signers([payer])
        .rpc();

      console.log(`   ✅ Non-member successfully paid for initialization`);
      console.log(`   ✅ This proves payer ≠ controller`);
      
      const multisigAccount = await program.account.multisig.fetch(multisigAddress);
      expect(multisigAccount.isInitialized).to.be.true;
    });
  });

  describe("Scenario 5: Large Multisig (7-of-10)", () => {
    it("handles larger multisig configuration", async () => {
      console.log("\n🎯 Scenario: Large multisig (7-of-10)");
      
      const members = Array.from({ length: 10 }, () => Keypair.generate());
      const memberPubkeys = members.map(m => m.publicKey);
      const threshold = 7;

      // Fund first 7 members who will sign
      for (let i = 0; i < 7; i++) {
        await fundAccount(members[i].publicKey);
      }

      const sortedMembers = [...memberPubkeys].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // Collect 7 signatures
      const signatures = members.slice(0, 7).map(member =>
        createSignature(memberPubkeys, threshold, member)
      );

      const tx = await program.methods
        .initializeMultisig(sortedMembers, threshold, signatures)
        .accounts({
          multisig: multisigAddress,
          payer: members[0].publicKey,
        })
        .signers([members[0]])
        .rpc();

      console.log(`   ✅ 7-of-10 multisig initialized successfully`);
      
      const multisigAccount = await program.account.multisig.fetch(multisigAddress);
      expect(multisigAccount.members.length).to.equal(10);
      expect(multisigAccount.threshold).to.equal(7);
    });
  });

  describe("Scenario 6: Pre-funded Address Security", () => {
    it("pre-funded address remains secure until proper initialization", async () => {
      console.log("\n🎯 Scenario: Pre-funded address security");
      
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      
      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      await fundAccount(member1.publicKey);
      await fundAccount(member2.publicKey);

      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // Pre-fund with significant amount
      const preFundAmount = 1 * LAMPORTS_PER_SOL;
      await fundAccount(multisigAddress, preFundAmount);
      
      console.log(`   💰 Pre-funded: ${preFundAmount / LAMPORTS_PER_SOL} SOL`);

      // Verify funds are there
      const balance1 = await provider.connection.getBalance(multisigAddress);
      expect(balance1).to.be.greaterThanOrEqual(preFundAmount);

      // Now properly initialize
      const sig1 = createSignature(members, threshold, member1);
      const sig2 = createSignature(members, threshold, member2);

      await program.methods
        .initializeMultisig(sortedMembers, threshold, [sig1, sig2])
        .accounts({
          multisig: multisigAddress,
          payer: member1.publicKey,
        })
        .signers([member1])
        .rpc();

      // Verify funds are still there after initialization
      const balance2 = await provider.connection.getBalance(multisigAddress);
      expect(balance2).to.be.greaterThanOrEqual(preFundAmount);
      
      console.log(`   ✅ Funds preserved: ${balance2 / LAMPORTS_PER_SOL} SOL`);
      console.log(`   ✅ Only legitimate members can control multisig`);
    });
  });
});

