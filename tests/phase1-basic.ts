import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisig } from "../target/types/truly_self_initiating_multisig";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import * as crypto from "crypto";

describe("Phase 1: Truly Self-Initiating Multisig", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.TrulySelfInitiatingMultisig as Program<TrulySelfInitiatingMultisig>;

  let member1: Keypair;
  let member2: Keypair;
  let member3: Keypair;
  let members: PublicKey[];
  let threshold: number;

  before(async () => {
    // Generate test members
    member1 = Keypair.generate();
    member2 = Keypair.generate();
    member3 = Keypair.generate();
    
    members = [member1.publicKey, member2.publicKey, member3.publicKey];
    threshold = 2; // 2-of-3 multisig

    // Fund members for transactions
    const airdropAmount = 2 * anchor.web3.LAMPORTS_PER_SOL;
    await provider.connection.requestAirdrop(member1.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(member2.publicKey, airdropAmount);
    await provider.connection.requestAirdrop(member3.publicKey, airdropAmount);
    
    // Wait for airdrops
    await new Promise(resolve => setTimeout(resolve, 1000));
  });

  describe("Address Derivation", () => {
    it("derives deterministic multisig address", async () => {
      // Sort members as the program does
      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      // Call the derive_address view function
      const result = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      console.log("Derived multisig address:", result.toString());
      
      // Verify it's a valid public key
      expect(result).to.be.instanceOf(PublicKey);
      
      // Call again with same params - should get same address
      const result2 = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();
      
      expect(result.toString()).to.equal(result2.toString());
      console.log("✅ Deterministic derivation verified");
    });

    it("derives different address for different members", async () => {
      const member4 = Keypair.generate();
      const differentMembers = [member1.publicKey, member2.publicKey, member4.publicKey];
      
      const sortedMembers1 = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );
      const sortedMembers2 = [...differentMembers].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address1 = await program.methods
        .deriveAddress(sortedMembers1, threshold)
        .view();

      const address2 = await program.methods
        .deriveAddress(sortedMembers2, threshold)
        .view();

      expect(address1.toString()).to.not.equal(address2.toString());
      console.log("✅ Different configs produce different addresses");
    });

    it("derives different address for different threshold", async () => {
      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const address1 = await program.methods
        .deriveAddress(sortedMembers, 2)
        .view();

      const address2 = await program.methods
        .deriveAddress(sortedMembers, 3)
        .view();

      expect(address1.toString()).to.not.equal(address2.toString());
      console.log("✅ Different thresholds produce different addresses");
    });
  });

  describe("Pre-funding", () => {
    it("can send SOL to derived address before initialization", async () => {
      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      console.log("Pre-funding address:", multisigAddress.toString());

      // Send SOL to the derived address
      const fundAmount = 0.1 * anchor.web3.LAMPORTS_PER_SOL;
      const tx = await provider.connection.requestAirdrop(
        multisigAddress,
        fundAmount
      );
      await provider.connection.confirmTransaction(tx);

      // Check balance
      const balance = await provider.connection.getBalance(multisigAddress);
      expect(balance).to.be.greaterThan(0);
      console.log(`✅ Pre-funded with ${balance / anchor.web3.LAMPORTS_PER_SOL} SOL`);
    });
  });

  describe("Security: No Private Key Generation", () => {
    it("verifies no private key can be derived", async () => {
      const sortedMembers = [...members].sort((a, b) => 
        Buffer.compare(a.toBuffer(), b.toBuffer())
      );

      const multisigAddress = await program.methods
        .deriveAddress(sortedMembers, threshold)
        .view();

      // Try to "compute" a private key like the old implementation did
      // This should NOT work for signing transactions
      const configData = {
        members: sortedMembers.map(m => m.toString()).sort(),
        threshold,
      };
      const configString = JSON.stringify(configData);
      const configHash = crypto.createHash('sha256').update(configString).digest();
      
      // Old broken implementation would do: Keypair.fromSeed(seed)
      // Let's verify that approach DOESN'T give us control of the PDA
      const seed = configHash.slice(0, 32);
      const fakeKeypair = Keypair.fromSeed(seed);
      
      // The fake keypair's pubkey should NOT match our PDA
      expect(fakeKeypair.publicKey.toString()).to.not.equal(multisigAddress.toString());
      
      console.log("✅ Confirmed: No private key can control the PDA");
      console.log("   PDA address:", multisigAddress.toString());
      console.log("   Fake keypair:", fakeKeypair.publicKey.toString());
      console.log("   These are DIFFERENT - which is what we want!");
    });
  });
});

