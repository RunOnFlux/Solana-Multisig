import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisig } from "../target/types/truly_self_initiating_multisig";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";

/**
 * Phase 4: Unit Tests
 * Tests individual components and functions
 */
describe("Unit Tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace
    .TrulySelfInitiatingMultisig as Program<TrulySelfInitiatingMultisig>;

  describe("PDA Derivation Tests", () => {
    it("derives consistent addresses for same configuration", async () => {
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();

      const members = [member1.publicKey, member2.publicKey, member3.publicKey];
      const threshold = 2;

      // Sort members
      const sortedMembers = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      // Derive twice
      const address1 = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      const address2 = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      expect(address1.toString()).to.equal(address2.toString());
      console.log(`✅ Consistent derivation: ${address1.toString()}`);
    });

    it("derives different addresses for different member order (but same sorted)", async () => {
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();

      // Different order
      const members1 = [
        member1.publicKey,
        member2.publicKey,
        member3.publicKey,
      ];
      const members2 = [
        member3.publicKey,
        member1.publicKey,
        member2.publicKey,
      ];

      const threshold = 2;

      // Sort both
      const sorted1 = [...members1].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );
      const sorted2 = [...members2].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address1 = await program.methods
        .deriveAddress(sorted1, threshold)
        .view();

      const address2 = await program.methods
        .deriveAddress(sorted2, threshold)
        .view();

      // Should be the same because sorting normalizes order
      expect(address1.toString()).to.equal(address2.toString());
      console.log(`✅ Order-independent derivation: ${address1.toString()}`);
    });

    it("derives different addresses for different members", async () => {
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();
      const member4 = Keypair.generate();

      const members1 = [
        member1.publicKey,
        member2.publicKey,
        member3.publicKey,
      ];
      const members2 = [
        member1.publicKey,
        member2.publicKey,
        member4.publicKey,
      ];

      const threshold = 2;

      const sorted1 = [...members1].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );
      const sorted2 = [...members2].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address1 = await program.methods
        .deriveAddress(sorted1, threshold)
        .view();

      const address2 = await program.methods
        .deriveAddress(sorted2, threshold)
        .view();

      expect(address1.toString()).to.not.equal(address2.toString());
      console.log(`✅ Different members = different addresses`);
    });

    it("derives different addresses for different thresholds", async () => {
      const member1 = Keypair.generate();
      const member2 = Keypair.generate();
      const member3 = Keypair.generate();

      const members = [member1.publicKey, member2.publicKey, member3.publicKey];

      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address1 = await program.methods.deriveAddress(sorted, 2).view();

      const address2 = await program.methods.deriveAddress(sorted, 3).view();

      expect(address1.toString()).to.not.equal(address2.toString());
      console.log(`✅ Different thresholds = different addresses`);
    });
  });

  describe("Threshold Validation Tests", () => {
    it("should work with threshold = 1 (1-of-N)", async () => {
      const members = Array.from(
        { length: 5 },
        () => Keypair.generate().publicKey
      );
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 1).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ 1-of-5 multisig supported`);
    });

    it("should work with threshold = N (N-of-N)", async () => {
      const members = Array.from(
        { length: 5 },
        () => Keypair.generate().publicKey
      );
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 5).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ 5-of-5 multisig supported`);
    });

    it("should work with common configurations", async () => {
      const configs = [
        { n: 2, m: 3, name: "2-of-3" },
        { n: 3, m: 5, name: "3-of-5" },
        { n: 4, m: 7, name: "4-of-7" },
        { n: 5, m: 9, name: "5-of-9" },
      ];

      for (const config of configs) {
        const members = Array.from(
          { length: config.m },
          () => Keypair.generate().publicKey
        );
        const sorted = [...members].sort((a, b) =>
          Buffer.compare(a.toBuffer(), b.toBuffer())
        );

        const address = await program.methods
          .deriveAddress(sorted, config.n)
          .view();

        expect(address).to.be.instanceOf(PublicKey);
        console.log(
          `✅ ${config.name} multisig: ${address.toString().slice(0, 16)}...`
        );
      }
    });
  });

  describe("Member Count Tests", () => {
    it("should support minimum members (2)", async () => {
      const members = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 1).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ 2-member multisig supported`);
    });

    it("should support maximum members (20)", async () => {
      const members = Array.from(
        { length: 20 },
        () => Keypair.generate().publicKey
      );
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 8).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ 20-member multisig supported`);
    });

    it("should support 8-of-15 multisig", async () => {
      const members = Array.from(
        { length: 15 },
        () => Keypair.generate().publicKey
      );
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 8).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ 8-of-15 multisig supported`);
    });
  });

  describe("Edge Cases", () => {
    it("handles all identical public keys (should be caught by duplicate check)", async () => {
      const samePubkey = Keypair.generate().publicKey;
      const members = [samePubkey, samePubkey, samePubkey];

      // This will derive an address, but initialization should fail
      const address = await program.methods.deriveAddress(members, 2).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(
        `✅ Can derive address even with duplicates (init will reject)`
      );
    });

    it("handles maximum threshold (all members must sign)", async () => {
      const members = Array.from(
        { length: 5 },
        () => Keypair.generate().publicKey
      );
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 5).view();

      expect(address).to.be.instanceOf(PublicKey);
      console.log(`✅ Maximum threshold (5-of-5) works`);
    });

    it("verifies PDA is valid Solana address", async () => {
      const members = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address = await program.methods.deriveAddress(sorted, 2).view();

      // Verify it's a valid public key
      expect(() => new PublicKey(address)).to.not.throw();

      // Verify it's 32 bytes
      expect(address.toBytes()).to.have.lengthOf(32);

      console.log(`✅ Derived PDA is valid Solana address`);
    });
  });

  describe("Determinism Tests", () => {
    it("same config produces same address across multiple calls", async () => {
      const members = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );
      const threshold = 2;

      const addresses = [];
      for (let i = 0; i < 10; i++) {
        const address = await program.methods
          .deriveAddress(sorted, threshold)
          .view();
        addresses.push(address.toString());
      }

      // All addresses should be identical
      const uniqueAddresses = new Set(addresses);
      expect(uniqueAddresses.size).to.equal(1);
      console.log(`✅ Derived same address 10 times: ${addresses[0]}`);
    });

    it("different program instances produce same address", async () => {
      const members = [
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ];
      const sorted = [...members].sort((a, b) =>
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      // Call from program
      const address1 = await program.methods.deriveAddress(sorted, 1).view();

      // Manually calculate using same logic
      const memberHash = require("crypto").createHash("sha256");
      for (const member of sorted) {
        memberHash.update(member.toBytes());
      }
      const hash = memberHash.digest();

      const [address2] = PublicKey.findProgramAddressSync(
        [Buffer.from("multisig"), hash, Buffer.from([1])],
        program.programId
      );

      expect(address1.toString()).to.equal(address2.toString());
      console.log(`✅ Manual calculation matches program derivation`);
    });
  });
});
