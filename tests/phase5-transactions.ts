import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisig } from "../target/types/truly_self_initiating_multisig";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import { expect } from "chai";
import * as crypto from "crypto";
import * as nacl from "tweetnacl";

/**
 * Phase 5: Transaction Proposal Lifecycle (V0-style messages).
 *
 * Tests cover the rewritten create_transaction / approve_transaction /
 * execute_transaction flow using the V0 TransactionMessage format with
 * static account_keys + compiled instructions + (optional) ALT lookups.
 */
describe("Phase 5: Transaction Lifecycle", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace
    .TrulySelfInitiatingMultisig as Program<TrulySelfInitiatingMultisig>;
  const programId = program.programId;
  const ED25519_PROGRAM_ID = new PublicKey(
    "Ed25519SigVerify111111111111111111111111111"
  );

  // ============================================================
  // Helpers
  // ============================================================

  async function fund(pubkey: PublicKey, amount = 2 * LAMPORTS_PER_SOL) {
    try {
      const sig = await provider.connection.requestAirdrop(pubkey, amount);
      await provider.connection.confirmTransaction(sig);
      await new Promise((r) => setTimeout(r, 500));
    } catch {
      /* airdrop may rate-limit; tests handle insufficient funds */
    }
  }

  function sortMembers(members: PublicKey[]): PublicKey[] {
    return [...members].sort((a, b) =>
      Buffer.compare(a.toBuffer(), b.toBuffer())
    );
  }

  function buildInitMessage(members: PublicKey[], threshold: number): Buffer {
    const sorted = sortMembers(members);
    return Buffer.concat([
      Buffer.from("TRULY_SELF_INITIATING_MULTISIG_INIT"),
      ...sorted.map((m) => Buffer.from(m.toBytes())),
      Buffer.from([threshold]),
    ]);
  }

  function signInitMessage(
    members: PublicKey[],
    threshold: number,
    signer: Keypair
  ) {
    const message = buildInitMessage(members, threshold);
    const signature = nacl.sign.detached(message, signer.secretKey);
    const messageHash = crypto.createHash("sha256").update(message).digest();
    return {
      signer: signer.publicKey,
      signature: Array.from(signature),
      messageHash: Array.from(messageHash),
    };
  }

  // Build the Solana Ed25519 program "verify single signature" instruction.
  // Layout matches the program's verify_ed25519_signature parser.
  function makeEd25519VerifyIx(
    pubkey: PublicKey,
    message: Buffer,
    signature: Buffer
  ): TransactionInstruction {
    const PUBKEY_OFFSET = 16;
    const SIG_OFFSET = PUBKEY_OFFSET + 32;
    const MSG_OFFSET = SIG_OFFSET + 64;
    const data = Buffer.alloc(MSG_OFFSET + message.length);

    // Header.
    data.writeUInt8(1, 0); // num_signatures
    data.writeUInt8(0, 1); // padding

    // Signature entry (14 bytes).
    data.writeUInt16LE(SIG_OFFSET, 2); // signature_offset
    data.writeUInt16LE(0xffff, 4); // signature_instruction_index
    data.writeUInt16LE(PUBKEY_OFFSET, 6); // public_key_offset
    data.writeUInt16LE(0xffff, 8); // public_key_instruction_index
    data.writeUInt16LE(MSG_OFFSET, 10); // message_data_offset
    data.writeUInt16LE(message.length, 12); // message_data_size
    data.writeUInt16LE(0xffff, 14); // message_instruction_index

    pubkey.toBuffer().copy(data, PUBKEY_OFFSET);
    signature.copy(data, SIG_OFFSET);
    message.copy(data, MSG_OFFSET);

    return new TransactionInstruction({
      keys: [],
      programId: ED25519_PROGRAM_ID,
      data,
    });
  }

  const VAULT_PDA_SEED = Buffer.from("vault");

  function deriveVault(
    multisig: PublicKey,
    vaultIndex: number
  ): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [VAULT_PDA_SEED, multisig.toBuffer(), Buffer.from([vaultIndex])],
      programId
    );
  }

  /**
   * Set up a fresh multisig: derive address, pre-fund the vault (vault_index=0),
   * collect signatures, submit init tx with Ed25519 verify ixs preceding the
   * program ix. Returns the multisig PDA + vault PDA + funding context.
   */
  async function setupMultisig(opts: {
    memberCount: number;
    threshold: number;
    /** Lamports to pre-fund the vault (vault_index=0). */
    preFundVaultLamports?: number;
  }): Promise<{
    members: Keypair[];
    sortedMemberKeys: PublicKey[];
    threshold: number;
    multisig: PublicKey;
    vault: PublicKey;
    vaultBump: number;
  }> {
    const members = Array.from({ length: opts.memberCount }, () =>
      Keypair.generate()
    );
    for (const m of members) await fund(m.publicKey);

    const memberKeys = members.map((m) => m.publicKey);
    const sortedMemberKeys = sortMembers(memberKeys);

    const multisig: PublicKey = (await program.methods
      .deriveAddress(sortedMemberKeys, opts.threshold)
      .view()) as PublicKey;

    const [vault, vaultBump] = deriveVault(multisig, 0);

    if (opts.preFundVaultLamports && opts.preFundVaultLamports > 0) {
      const funder = Keypair.generate();
      await fund(
        funder.publicKey,
        opts.preFundVaultLamports + 1 * LAMPORTS_PER_SOL
      );
      const tx = new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: funder.publicKey,
          toPubkey: vault,
          lamports: opts.preFundVaultLamports,
        })
      );
      await anchor.web3.sendAndConfirmTransaction(provider.connection, tx, [
        funder,
      ]);
    }

    // Collect threshold signatures.
    const sigDatas = members
      .slice(0, opts.threshold)
      .map((m) => signInitMessage(memberKeys, opts.threshold, m));
    const message = buildInitMessage(memberKeys, opts.threshold);
    const ed25519Ixs = sigDatas.map((s) =>
      makeEd25519VerifyIx(s.signer, message, Buffer.from(s.signature))
    );

    const payer = members[0];
    await program.methods
      .initializeMultisig(sortedMemberKeys, opts.threshold, sigDatas)
      .accountsPartial({
        multisig,
        payer: payer.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .preInstructions(ed25519Ixs)
      .signers([payer])
      .rpc();

    return {
      members,
      sortedMemberKeys,
      threshold: opts.threshold,
      multisig,
      vault,
      vaultBump,
    };
  }

  /** Resolve the next transaction PDA for a given multisig. */
  async function nextTransactionPda(
    multisig: PublicKey,
    indexOverride?: bigint
  ): Promise<{ pda: PublicKey; index: bigint }> {
    let nextIndex: bigint;
    if (indexOverride !== undefined) {
      nextIndex = indexOverride;
    } else {
      const acc = await (program.account as any).multisig.fetch(multisig);
      nextIndex = BigInt(acc.transactionIndex.toString()) + BigInt(1);
    }
    const [pda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisig.toBuffer(),
        new anchor.BN(nextIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      programId
    );
    return { pda, index: nextIndex };
  }

  /**
   * Build a minimal V0 TransactionMessage that transfers `lamports` from the
   * multisig PDA to `recipient`.
   */
  function buildSolTransferMessage(
    vault: PublicKey,
    recipient: PublicKey,
    lamports: number
  ) {
    // account_keys layout:
    //   [0] vault (writable signer)
    //   [1] recipient (writable non-signer)
    //   [2] system_program (readonly non-signer)
    const accountKeys = [vault, recipient, SystemProgram.programId];

    // SystemProgram.transfer encoding: 4 bytes discriminator (2 LE) + 8 bytes amount LE.
    const data = Buffer.alloc(12);
    data.writeUInt32LE(2, 0); // 2 = Transfer instruction
    data.writeBigUInt64LE(BigInt(lamports), 4);

    return {
      numSigners: 1,
      numWritableSigners: 1,
      numWritableNonSigners: 1,
      accountKeys,
      instructions: [
        {
          programIdIndex: 2, // system_program
          accountIndexes: Buffer.from([0, 1]), // [from, to]
          data,
        },
      ],
      addressTableLookups: [] as any[],
    };
  }

  // ============================================================
  // create_transaction
  // ============================================================
  describe("create_transaction", () => {
    it("creates a proposal from a member with a valid SOL-transfer message", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        0.1 * LAMPORTS_PER_SOL
      );
      const { pda, index } = await nextTransactionPda(multisig);

      await program.methods
        .createTransaction(0, message as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      const tx = await (program.account as any).vaultTransaction.fetch(pda);
      expect(tx.transactionIndex.toString()).to.equal(index.toString());
      expect((tx.creator as PublicKey).toBase58()).to.equal(
        members[0].publicKey.toBase58()
      );
      expect(tx.executed).to.equal(false);
      expect(tx.approvals.length).to.equal(0);
      expect(tx.message.accountKeys.length).to.equal(3);
    });

    it("rejects a non-member creator", async () => {
      const { multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const stranger = Keypair.generate();
      await fund(stranger.publicKey);
      const recipient = Keypair.generate();
      const message = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        0.1 * LAMPORTS_PER_SOL
      );
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
        await program.methods
          .createTransaction(0, message as any)
          .accountsPartial({
            multisig,
            transaction: pda,
            creator: stranger.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([stranger])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/UnauthorizedMember|6009|0x1779/);
      }
      expect(threw, "expected UnauthorizedMember error").to.equal(true);
    });

    it("rejects a message whose account_keys[0] is not the vault PDA", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      // Bad ordering: recipient first instead of vault.
      const badMessage = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [recipient.publicKey, vault, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([1, 0]),
            data: Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
        await program.methods
          .createTransaction(0, badMessage as any)
          .accountsPartial({
            multisig,
            transaction: pda,
            creator: members[0].publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw).to.equal(true);
    });

    it("rejects duplicate account_keys", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const dupMessage = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 2,
        // recipient appears twice.
        accountKeys: [
          vault,
          recipient.publicKey,
          recipient.publicKey,
          SystemProgram.programId,
        ],
        instructions: [
          {
            programIdIndex: 3,
            accountIndexes: Buffer.from([0, 1]),
            data: Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
        await program.methods
          .createTransaction(0, dupMessage as any)
          .accountsPartial({
            multisig,
            transaction: pda,
            creator: members[0].publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw).to.equal(true);
    });

    it("rejects program_id_index pointing to the vault PDA (index 0)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const badMessage = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 0, // BAD: points to vault PDA
            accountIndexes: Buffer.from([0, 1]),
            data: Buffer.alloc(0),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
        await program.methods
          .createTransaction(0, badMessage as any)
          .accountsPartial({
            multisig,
            transaction: pda,
            creator: members[0].publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw).to.equal(true);
    });

    it("two proposals in flight get distinct indexes (atomic counter)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const r1 = Keypair.generate();
      const r2 = Keypair.generate();

      // First proposal — index N+1.
      const m1 = buildSolTransferMessage(vault, r1.publicKey, 1000);
      const t1 = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, m1 as any)
        .accountsPartial({
          multisig,
          transaction: t1.pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      // Second proposal — must be at index N+2 (counter incremented at create).
      const m2 = buildSolTransferMessage(multisig, r2.publicKey, 2000);
      const t2 = await nextTransactionPda(multisig);
      expect(t2.index.toString()).to.equal(
        (t1.index + BigInt(1)).toString(),
        "counter must have advanced"
      );
      await program.methods
        .createTransaction(0, m2 as any)
        .accountsPartial({
          multisig,
          transaction: t2.pda,
          creator: members[1].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[1]])
        .rpc();

      const acc1 = await (program.account as any).vaultTransaction.fetch(
        t1.pda
      );
      const acc2 = await (program.account as any).vaultTransaction.fetch(
        t2.pda
      );
      expect(acc1.transactionIndex.toString()).to.equal(t1.index.toString());
      expect(acc2.transactionIndex.toString()).to.equal(t2.index.toString());
      expect(acc1.transactionIndex.toString()).to.not.equal(
        acc2.transactionIndex.toString()
      );
    });
  });

  // ============================================================
  // approve_transaction
  // ============================================================
  describe("approve_transaction", () => {
    it("happy path: a member approves a pending proposal", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(vault, recipient.publicKey, 1000);
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      // members[1] approves.
      await program.methods
        .approveTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          member: members[1].publicKey,
        })
        .signers([members[1]])
        .rpc();

      const tx = await (program.account as any).vaultTransaction.fetch(pda);
      expect(tx.approvals.length).to.equal(1);
      expect((tx.approvals[0] as PublicKey).toBase58()).to.equal(
        members[1].publicKey.toBase58()
      );
    });

    it("rejects approve from a non-member", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const stranger = Keypair.generate();
      await fund(stranger.publicKey);
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(vault, recipient.publicKey, 1000);
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      let threw = false;
      try {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: stranger.publicKey,
          })
          .signers([stranger])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/UnauthorizedMember/);
      }
      expect(threw).to.equal(true);
    });

    it("rejects double-approve from the same member", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(vault, recipient.publicKey, 1000);
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      await program.methods
        .approveTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          member: members[1].publicKey,
        })
        .signers([members[1]])
        .rpc();

      let threw = false;
      try {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: members[1].publicKey,
          })
          .signers([members[1]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/AlreadyApproved/);
      }
      expect(threw).to.equal(true);
    });
  });

  // ============================================================
  // execute_transaction
  // ============================================================
  describe("execute_transaction", () => {
    it("executes a 2-of-3 SOL transfer end-to-end", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const transferLamports = 0.1 * LAMPORTS_PER_SOL;

      const msg = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        transferLamports
      );
      const { pda, index } = await nextTransactionPda(multisig);

      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();

      // 2 approvals (creator + members[1]).
      for (const m of [members[0], members[1]]) {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: m.publicKey,
          })
          .signers([m])
          .rpc();
      }

      const balBefore = await provider.connection.getBalance(
        recipient.publicKey
      );

      await program.methods
        .executeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          executor: members[0].publicKey,
        })
        .remainingAccounts([
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ])
        .signers([members[0]])
        .rpc();

      const balAfter = await provider.connection.getBalance(
        recipient.publicKey
      );
      expect(balAfter - balBefore).to.equal(transferLamports);

      const tx = await (program.account as any).vaultTransaction.fetch(pda);
      expect(tx.executed).to.equal(true);
    });

    it("rejects execute when below threshold approvals", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(vault, recipient.publicKey, 1000);
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();
      // Only 1 approval (need 2).
      await program.methods
        .approveTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          member: members[0].publicKey,
        })
        .signers([members[0]])
        .rpc();

      let threw = false;
      try {
        await program.methods
          .executeTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            executor: members[0].publicKey,
          })
          .remainingAccounts([
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
            {
              pubkey: SystemProgram.programId,
              isSigner: false,
              isWritable: false,
            },
          ])
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InsufficientApprovals/);
      }
      expect(threw).to.equal(true);
    });

    it("rejects double-execute (already executed)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        0.05 * LAMPORTS_PER_SOL
      );
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();
      for (const m of [members[0], members[1]]) {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: m.publicKey,
          })
          .signers([m])
          .rpc();
      }
      const remaining = [
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ];
      await program.methods
        .executeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          executor: members[0].publicKey,
        })
        .remainingAccounts(remaining)
        .signers([members[0]])
        .rpc();

      let threw = false;
      try {
        await program.methods
          .executeTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            executor: members[0].publicKey,
          })
          .remainingAccounts(remaining)
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/AlreadyExecuted/);
      }
      expect(threw).to.equal(true);
    });

    it("rejects approve after execute", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        0.05 * LAMPORTS_PER_SOL
      );
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();
      for (const m of [members[0], members[1]]) {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: m.publicKey,
          })
          .signers([m])
          .rpc();
      }
      await program.methods
        .executeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          executor: members[0].publicKey,
        })
        .remainingAccounts([
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ])
        .signers([members[0]])
        .rpc();

      let threw = false;
      try {
        // Third member tries to approve after execution.
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: members[2].publicKey,
          })
          .signers([members[2]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/AlreadyExecuted/);
      }
      expect(threw).to.equal(true);
    });

    it("executes a multi-instruction proposal (transfer to two recipients)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const r1 = Keypair.generate();
      const r2 = Keypair.generate();
      const a1 = 0.05 * LAMPORTS_PER_SOL;
      const a2 = 0.07 * LAMPORTS_PER_SOL;

      const data1 = Buffer.alloc(12);
      data1.writeUInt32LE(2, 0);
      data1.writeBigUInt64LE(BigInt(a1), 4);
      const data2 = Buffer.alloc(12);
      data2.writeUInt32LE(2, 0);
      data2.writeBigUInt64LE(BigInt(a2), 4);

      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 2,
        accountKeys: [
          vault,
          r1.publicKey,
          r2.publicKey,
          SystemProgram.programId,
        ],
        instructions: [
          {
            programIdIndex: 3,
            accountIndexes: Buffer.from([0, 1]),
            data: data1,
          },
          {
            programIdIndex: 3,
            accountIndexes: Buffer.from([0, 2]),
            data: data2,
          },
        ],
        addressTableLookups: [],
      };
      const { pda, index } = await nextTransactionPda(multisig);

      await program.methods
        .createTransaction(0, message as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();
      for (const m of [members[0], members[1]]) {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: m.publicKey,
          })
          .signers([m])
          .rpc();
      }
      const before1 = await provider.connection.getBalance(r1.publicKey);
      const before2 = await provider.connection.getBalance(r2.publicKey);

      await program.methods
        .executeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          executor: members[0].publicKey,
        })
        .remainingAccounts([
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: r1.publicKey, isSigner: false, isWritable: true },
          { pubkey: r2.publicKey, isSigner: false, isWritable: true },
          {
            pubkey: SystemProgram.programId,
            isSigner: false,
            isWritable: false,
          },
        ])
        .signers([members[0]])
        .rpc();

      const after1 = await provider.connection.getBalance(r1.publicKey);
      const after2 = await provider.connection.getBalance(r2.publicKey);
      expect(after1 - before1).to.equal(a1);
      expect(after2 - before2).to.equal(a2);
    });

    it("rejects execute when remaining_accounts misorders the static section", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const msg = buildSolTransferMessage(
        vault,
        recipient.publicKey,
        0.05 * LAMPORTS_PER_SOL
      );
      const { pda, index } = await nextTransactionPda(multisig);
      await program.methods
        .createTransaction(0, msg as any)
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([members[0]])
        .rpc();
      for (const m of [members[0], members[1]]) {
        await program.methods
          .approveTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            member: m.publicKey,
          })
          .signers([m])
          .rpc();
      }

      // Swap static[0] and static[1] — should fail AccountMismatch.
      let threw = false;
      try {
        await program.methods
          .executeTransaction(new anchor.BN(index.toString()))
          .accountsPartial({
            multisig,
            transaction: pda,
            executor: members[0].publicKey,
          })
          .remainingAccounts([
            { pubkey: recipient.publicKey, isSigner: false, isWritable: true }, // wrong slot
            { pubkey: vault, isSigner: false, isWritable: true },
            {
              pubkey: SystemProgram.programId,
              isSigner: false,
              isWritable: false,
            },
          ])
          .signers([members[0]])
          .rpc();
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/AccountMismatch/);
      }
      expect(threw).to.equal(true);
    });
  });
});
