import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TrulySelfInitiatingMultisig } from "../target/types/truly_self_initiating_multisig";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddressSync,
  mintTo,
  createAssociatedTokenAccountInstruction,
  createTransferInstruction,
  getAccount,
} from "@solana/spl-token";
import { expect } from "chai";
import { setupMultisigViaAlt } from "./_helpers";

/**
 * Phase 6: Extra coverage gaps identified during round 8 audit.
 *
 *  - create_transaction validation edges (num_signers / num_writable_*).
 *  - MAX_TX_INSTRUCTIONS / MAX_TX_ACCOUNT_KEYS boundary cases.
 *  - SPL token transfer from a vault PDA (end-to-end).
 */
describe("Phase 6: Extra coverage", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace
    .TrulySelfInitiatingMultisig as Program<TrulySelfInitiatingMultisig>;
  const programId = program.programId;

  // ============================================================
  // Shared helpers.
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

  async function setupMultisig(opts: {
    memberCount: number;
    threshold: number;
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

    const sortedMemberKeys = [...members.map((m) => m.publicKey)].sort((a, b) =>
      Buffer.compare(a.toBuffer(), b.toBuffer())
    );

    const { multisig } = await setupMultisigViaAlt({
      program,
      connection: provider.connection,
      members,
      threshold: opts.threshold,
    });

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

    return {
      members,
      sortedMemberKeys,
      threshold: opts.threshold,
      multisig,
      vault,
      vaultBump,
    };
  }

  async function nextTransactionPda(
    multisig: PublicKey
  ): Promise<{ pda: PublicKey; index: bigint }> {
    const acc = await (program.account as any).multisig.fetch(multisig);
    const nextIndex = BigInt(acc.transactionIndex.toString()) + BigInt(1);
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

  /** SystemProgram.transfer encoding (4-byte discriminator + 8-byte amount LE). */
  function systemTransferData(lamports: number | bigint): Buffer {
    const data = Buffer.alloc(12);
    data.writeUInt32LE(2, 0);
    data.writeBigUInt64LE(BigInt(lamports), 4);
    return data;
  }

  // ============================================================
  // create_transaction — message validation edges
  // ============================================================
  describe("create_transaction validation edges", () => {
    it("rejects num_signers = 0 (vault must sign)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 0, // illegal
        numWritableSigners: 0,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([0, 1]),
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });

    it("rejects num_writable_signers > num_signers", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 1,
        numWritableSigners: 2, // illegal: > num_signers
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([0, 1]),
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });

    it("rejects num_writable_non_signers exceeding non-signer slots", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 5, // only 2 non-signer slots exist
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([0, 1]),
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });

    it("rejects program_id_index pointing at the vault (index 0)", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 0, // illegal: vault is not a program
            accountIndexes: Buffer.from([0, 1]),
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });

    it("rejects an account_indexes entry that is out of bounds", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([0, 99]), // 99 >> combined_count
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });

    it("rejects duplicate entries in account_keys", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        // recipient appears twice — wasteful, likely a client bug.
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
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(threw, "expected InvalidMessage").to.equal(true);
    });
  });

  // ============================================================
  // create_transaction — ALT lookups disallowed (Option D security gate)
  // ============================================================
  describe("address_table_lookups must be empty", () => {
    it("rejects a proposal with non-empty address_table_lookups", async () => {
      // Critical regression guard. If the program ever accepts ALT lookups
      // inside proposal messages, an executor could substitute a different
      // ALT at execute time and redirect CPIs to attacker-controlled
      // addresses. The program must reject any proposal that even attempts
      // to reference accounts via ALT.
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();

      // A "looks valid" proposal — except for one populated ALT lookup.
      const fakeAltKey = Keypair.generate().publicKey;
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: [
          {
            programIdIndex: 2,
            accountIndexes: Buffer.from([0, 1]),
            data: systemTransferData(1000),
          },
        ],
        addressTableLookups: [
          {
            accountKey: fakeAltKey,
            writableIndexes: Buffer.from([]),
            readonlyIndexes: Buffer.from([0]),
          },
        ],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        expect(String(e)).to.match(/InvalidMessage/);
      }
      expect(
        threw,
        "expected InvalidMessage rejection of ALT lookups"
      ).to.equal(true);
    });
  });

  // ============================================================
  // create_transaction — MAX_TX_INSTRUCTIONS boundary
  // ============================================================
  describe("MAX_TX_INSTRUCTIONS boundary", () => {
    const MAX_TX_INSTRUCTIONS = 16;

    it("accepts exactly MAX_TX_INSTRUCTIONS instructions", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const ixs = Array.from({ length: MAX_TX_INSTRUCTIONS }, () => ({
        programIdIndex: 2,
        accountIndexes: Buffer.from([0, 1]),
        data: systemTransferData(1),
      }));
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: ixs,
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

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
      expect(tx.message.instructions.length).to.equal(MAX_TX_INSTRUCTIONS);
    });

    it("rejects MAX_TX_INSTRUCTIONS + 1 instructions", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        preFundVaultLamports: 0.1 * LAMPORTS_PER_SOL,
      });
      const recipient = Keypair.generate();
      const ixs = Array.from({ length: MAX_TX_INSTRUCTIONS + 1 }, () => ({
        programIdIndex: 2,
        accountIndexes: Buffer.from([0, 1]),
        data: systemTransferData(1),
      }));
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 1,
        accountKeys: [vault, recipient.publicKey, SystemProgram.programId],
        instructions: ixs,
        addressTableLookups: [],
      };
      const { pda } = await nextTransactionPda(multisig);

      let threw = false;
      try {
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
      } catch (e: any) {
        threw = true;
        // The Anchor borsh deserializer rejects oversized Vec before our
        // own require_msg! check fires, so we accept either signal.
        expect(String(e)).to.match(/InvalidMessage|deserialize|too large/i);
      }
      expect(threw, "expected oversized instructions to fail").to.equal(true);
    });
  });

  // ============================================================
  // SPL token transfer from vault — end-to-end
  // ============================================================
  describe("SPL token transfer from vault", () => {
    it("transfers SPL tokens out of a vault PDA via multisig execute", async () => {
      const { members, multisig, vault } = await setupMultisig({
        memberCount: 3,
        threshold: 2,
        // Cover rent for the vault's ATA + a bit of headroom.
        preFundVaultLamports: 0.05 * LAMPORTS_PER_SOL,
      });

      // Mint authority + funder.
      const mintAuthority = Keypair.generate();
      await fund(mintAuthority.publicKey, 2 * LAMPORTS_PER_SOL);

      // Create a fresh SPL mint (6 decimals).
      const mint = await createMint(
        provider.connection,
        mintAuthority,
        mintAuthority.publicKey,
        null,
        6
      );

      // Vault's ATA (owner=vault PDA). The vault is system-owned with no data,
      // which is what spl-token's "owner" means — owner is just the
      // authority pubkey stored inside the token account, not the account's
      // on-chain owner program.
      const vaultAta = getAssociatedTokenAddressSync(mint, vault, true);
      const createVaultAtaIx = createAssociatedTokenAccountInstruction(
        mintAuthority.publicKey,
        vaultAta,
        vault,
        mint
      );
      const ataTx = new anchor.web3.Transaction().add(createVaultAtaIx);
      await anchor.web3.sendAndConfirmTransaction(provider.connection, ataTx, [
        mintAuthority,
      ]);

      // Mint 1,000,000 base units to the vault ATA.
      const startingBalance = BigInt(1_000_000);
      await mintTo(
        provider.connection,
        mintAuthority,
        mint,
        vaultAta,
        mintAuthority,
        startingBalance
      );

      // Recipient is a fresh wallet; create their ATA outside the proposal
      // (the multisig only signs the transfer, not the ATA creation).
      const recipientOwner = Keypair.generate();
      await fund(recipientOwner.publicKey, 1 * LAMPORTS_PER_SOL);
      const recipientAtaAccount = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        recipientOwner,
        mint,
        recipientOwner.publicKey
      );
      const recipientAta = recipientAtaAccount.address;

      // Build a token::transfer instruction with vault as the authority.
      const transferAmount = BigInt(250_000);
      const transferIx = createTransferInstruction(
        vaultAta,
        recipientAta,
        vault,
        transferAmount
      );

      // Compile into the V0 message format.
      // account_keys layout:
      //   [0] vault (writable signer — required for authority)
      //   [1] vault ATA (writable non-signer)
      //   [2] recipient ATA (writable non-signer)
      //   [3] token program (readonly non-signer)
      const message = {
        numSigners: 1,
        numWritableSigners: 1,
        numWritableNonSigners: 2,
        accountKeys: [vault, vaultAta, recipientAta, TOKEN_PROGRAM_ID],
        instructions: [
          {
            programIdIndex: 3,
            // Token transfer expects: [source, dest, authority]
            accountIndexes: Buffer.from([1, 2, 0]),
            data: Buffer.from(transferIx.data),
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

      const balBefore = (await getAccount(provider.connection, recipientAta))
        .amount;

      await program.methods
        .executeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          executor: members[0].publicKey,
        })
        .remainingAccounts([
          { pubkey: vault, isSigner: false, isWritable: true },
          { pubkey: vaultAta, isSigner: false, isWritable: true },
          { pubkey: recipientAta, isSigner: false, isWritable: true },
          { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        ])
        .signers([members[0]])
        .rpc();

      const balAfter = (await getAccount(provider.connection, recipientAta))
        .amount;
      const vaultAfter = (await getAccount(provider.connection, vaultAta))
        .amount;

      expect((balAfter - balBefore).toString()).to.equal(
        transferAmount.toString()
      );
      expect(vaultAfter.toString()).to.equal(
        (startingBalance - transferAmount).toString()
      );

      const tx = await (program.account as any).vaultTransaction.fetch(pda);
      expect(tx.executed).to.equal(true);
    });
  });
});
