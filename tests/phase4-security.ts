import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaMultisig } from "../target/types/solana_multisig";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import * as crypto from "crypto";

/**
 * Phase 4: Security & Attack Vector Testing — permissionless init model.
 *
 * Security model under test:
 *
 *   - Multisig PDA = find_program_address(
 *       [b"multisig", sha256(sorted_members), [threshold]], program_id)
 *     so the PDA address is fully determined by `(sorted_members, threshold)`.
 *
 *   - `initialize_multisig(member_hash, threshold, member_count)` is callable
 *     by anyone (the only signer is `payer`, who pays rent). The program
 *     recomputes `actual_hash = sha256(sorted(remaining_accounts))` and
 *     rejects if `actual_hash != member_hash` — this binds the on-chain
 *     stored member set to the PDA address.
 *
 *   - Fund safety is enforced by the threshold check on
 *     `create_transaction` / `approve_transaction` / `execute_transaction`
 *     (each verifies signers are members of the multisig; execute requires
 *     ≥ threshold approvals). Init does not gate funds; it only registers
 *     the canonical (members, threshold) pair at the canonical PDA.
 *
 *   - Pre-funding the vault is safe BEFORE init because nothing can move
 *     funds without going through create/approve/execute, all of which
 *     require a registered multisig — and the only multisig that can
 *     exist at the canonical PDA is the one with the canonical members.
 */
describe("Security Testing (permissionless init)", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaMultisig as Program<SolanaMultisig>;

  let member1: Keypair;
  let member2: Keypair;
  let member3: Keypair;
  let attacker: Keypair;
  let members: PublicKey[];
  let threshold: number;

  before(async () => {
    member1 = Keypair.generate();
    member2 = Keypair.generate();
    member3 = Keypair.generate();
    attacker = Keypair.generate();
    members = [member1.publicKey, member2.publicKey, member3.publicKey];
    threshold = 2;

    const airdropAmount = 2 * anchor.web3.LAMPORTS_PER_SOL;
    for (const m of [member1, member2, member3, attacker]) {
      try {
        const sig = await provider.connection.requestAirdrop(
          m.publicKey,
          airdropAmount
        );
        await provider.connection.confirmTransaction(sig);
      } catch {
        /* localnet may rate-limit; tests handle insufficient funds */
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  function sortMembers(ks: PublicKey[]): PublicKey[] {
    return [...ks].sort((a, b) => Buffer.compare(a.toBuffer(), b.toBuffer()));
  }
  function hashMembers(ks: PublicKey[]): Buffer {
    const h = crypto.createHash("sha256");
    for (const k of ks) h.update(k.toBytes());
    return h.digest();
  }

  async function derivePda(
    memberHash: Buffer,
    t: number
  ): Promise<[PublicKey, number]> {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("multisig"), memberHash, Buffer.from([t])],
      program.programId
    );
  }

  // ------------------------------------------------------------
  // Canonical PDA ↔ canonical members
  // ------------------------------------------------------------

  describe("Canonical PDA binding", () => {
    it("rejects init when member_hash arg doesn't match remaining_accounts hash", async () => {
      const canonical = sortMembers(members);
      const canonicalHash = hashMembers(canonical);
      const [pda] = await derivePda(canonicalHash, threshold);

      // Attacker passes the canonical hash (to land at the canonical PDA)
      // but tries to substitute their own pubkey into the member set.
      const tampered = sortMembers([
        member1.publicKey,
        member2.publicKey,
        attacker.publicKey, // ← swapped in
      ]);

      let err: unknown = null;
      try {
        await program.methods
          .initializeMultisig(
            Array.from(canonicalHash),
            threshold,
            tampered.length
          )
          .accountsPartial({
            multisig: pda,
            payer: attacker.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            tampered.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([attacker])
          .rpc();
      } catch (e) {
        err = e;
      }
      expect(err, "tamper attempt should fail").to.not.equal(null);
      expect(String(err)).to.match(/InvalidPDA|seeds constraint|ConstraintSeeds/i);
      console.log("   ✅ tampered member set rejected at canonical PDA");
    });

    it("front-running with the CANONICAL inputs is harmless (state ends identical)", async () => {
      const canonical = sortMembers(members);
      const canonicalHash = hashMembers(canonical);
      const [pda] = await derivePda(canonicalHash, threshold);

      // Attacker pays rent and initializes with the correct (canonical)
      // member set. This is exactly what we want — no harm done; in fact
      // they paid the rent for us.
      await program.methods
        .initializeMultisig(
          Array.from(canonicalHash),
          threshold,
          canonical.length
        )
        .accountsPartial({
          multisig: pda,
          payer: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(
          canonical.map((pk) => ({
            pubkey: pk,
            isSigner: false,
            isWritable: false,
          }))
        )
        .signers([attacker])
        .rpc();

      const acc = await program.account.multisig.fetch(pda);
      expect(acc.threshold).to.equal(threshold);
      expect(acc.members.length).to.equal(canonical.length);
      expect(
        acc.members.map((p: PublicKey) => p.toBase58()).sort()
      ).to.deep.equal(canonical.map((p) => p.toBase58()).sort());

      // Attempt to re-init must fail (account already exists).
      let reinitErr: unknown = null;
      try {
        await program.methods
          .initializeMultisig(
            Array.from(canonicalHash),
            threshold,
            canonical.length
          )
          .accountsPartial({
            multisig: pda,
            payer: member1.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            canonical.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([member1])
          .rpc();
      } catch (e) {
        reinitErr = e;
      }
      expect(reinitErr, "re-init must fail").to.not.equal(null);
      console.log(
        "   ✅ front-run with canonical inputs → canonical state stored; re-init blocked"
      );
    });

    it("attacker initing with their own members lands at a DIFFERENT PDA — does not affect canonical vault", async () => {
      // The attacker's "multisig" is at a totally different address and
      // has no relationship to the canonical (member1, member2, member3)
      // vault. Their init succeeds — but harmlessly.
      const attackerMembers = sortMembers([
        attacker.publicKey,
        Keypair.generate().publicKey,
      ]);
      const attackerHash = hashMembers(attackerMembers);
      const [attackerPda] = await derivePda(attackerHash, 1);

      const canonicalHash = hashMembers(sortMembers(members));
      const [canonicalPda] = await derivePda(canonicalHash, threshold);

      expect(attackerPda.toBase58()).to.not.equal(canonicalPda.toBase58());

      await program.methods
        .initializeMultisig(Array.from(attackerHash), 1, attackerMembers.length)
        .accountsPartial({
          multisig: attackerPda,
          payer: attacker.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .remainingAccounts(
          attackerMembers.map((pk) => ({
            pubkey: pk,
            isSigner: false,
            isWritable: false,
          }))
        )
        .signers([attacker])
        .rpc();
      console.log(
        "   ✅ attacker multisig lives at a separate address — canonical vault untouched"
      );
    });
  });

  // ------------------------------------------------------------
  // Argument validation
  // ------------------------------------------------------------

  describe("Init argument validation", () => {
    it("rejects threshold = 0", async () => {
      const newMembers = sortMembers([
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ]);
      const newHash = hashMembers(newMembers);
      const [pda] = await derivePda(newHash, 0);

      let err: unknown = null;
      try {
        await program.methods
          .initializeMultisig(Array.from(newHash), 0, newMembers.length)
          .accountsPartial({
            multisig: pda,
            payer: member1.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            newMembers.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([member1])
          .rpc();
      } catch (e) {
        err = e;
      }
      expect(err, "threshold=0 must fail").to.not.equal(null);
      expect(String(err)).to.match(/InvalidThreshold/i);
    });

    it("rejects threshold > member count", async () => {
      const newMembers = sortMembers([
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ]);
      const newHash = hashMembers(newMembers);
      const overThreshold = 5;
      const [pda] = await derivePda(newHash, overThreshold);

      let err: unknown = null;
      try {
        await program.methods
          .initializeMultisig(
            Array.from(newHash),
            overThreshold,
            newMembers.length
          )
          .accountsPartial({
            multisig: pda,
            payer: member1.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            newMembers.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([member1])
          .rpc();
      } catch (e) {
        err = e;
      }
      expect(err, "threshold > N must fail").to.not.equal(null);
      expect(String(err)).to.match(/InvalidThreshold/i);
    });

    it("rejects duplicate members", async () => {
      const dup = Keypair.generate().publicKey;
      const dupMembers = sortMembers([dup, dup]);
      const dupHash = hashMembers(dupMembers);
      const [pda] = await derivePda(dupHash, 2);

      let err: unknown = null;
      try {
        await program.methods
          .initializeMultisig(Array.from(dupHash), 2, dupMembers.length)
          .accountsPartial({
            multisig: pda,
            payer: member1.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            dupMembers.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([member1])
          .rpc();
      } catch (e) {
        err = e;
      }
      expect(err, "duplicate members must fail").to.not.equal(null);
      expect(String(err)).to.match(/DuplicateMembers/i);
    });

    it("rejects mismatched member_count arg vs remaining_accounts length", async () => {
      const newMembers = sortMembers([
        Keypair.generate().publicKey,
        Keypair.generate().publicKey,
      ]);
      const newHash = hashMembers(newMembers);
      const [pda] = await derivePda(newHash, 1);

      let err: unknown = null;
      try {
        await program.methods
          .initializeMultisig(
            Array.from(newHash),
            1,
            (newMembers.length + 1) as number // lie about count
          )
          .accountsPartial({
            multisig: pda,
            payer: member1.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts(
            newMembers.map((pk) => ({
              pubkey: pk,
              isSigner: false,
              isWritable: false,
            }))
          )
          .signers([member1])
          .rpc();
      } catch (e) {
        err = e;
      }
      expect(err, "member_count mismatch must fail").to.not.equal(null);
      expect(String(err)).to.match(/InvalidMemberCount/i);
    });
  });
});
