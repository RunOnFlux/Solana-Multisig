import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaMultisig } from "../target/types/solana_multisig";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { expect } from "chai";
import { setupMultisigViaAlt } from "./_helpers";

/**
 * Phase 7: close_transaction — garbage-collect executed proposal accounts
 * and refund their rent to the original creator.
 *
 * Without this instruction, every multisig send leaves a small (~0.007 SOL)
 * permanent rent deposit on-chain forever. With it, the wallet bundles
 * close_transaction into the same outer tx as execute_transaction and the
 * rent cycles back into the creator's leaf, keeping per-send fees minimal.
 */
describe("Phase 7: close_transaction", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaMultisig as Program<SolanaMultisig>;
  const programId = program.programId;

  const VAULT_PDA_SEED = Buffer.from("vault");

  async function fund(pubkey: PublicKey, amount = 2 * LAMPORTS_PER_SOL) {
    try {
      const sig = await provider.connection.requestAirdrop(pubkey, amount);
      await provider.connection.confirmTransaction(sig);
      await new Promise((r) => setTimeout(r, 500));
    } catch {
      /* airdrop may rate-limit; tests handle insufficient funds */
    }
  }

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
  }) {
    const members = Array.from({ length: opts.memberCount }, () =>
      Keypair.generate()
    );
    for (const m of members) await fund(m.publicKey);
    const { multisig } = await setupMultisigViaAlt({
      program,
      connection: provider.connection,
      members,
      threshold: opts.threshold,
    });
    const [vault] = deriveVault(multisig, 0);
    if (opts.preFundVaultLamports && opts.preFundVaultLamports > 0) {
      const funder = Keypair.generate();
      await fund(
        funder.publicKey,
        opts.preFundVaultLamports + LAMPORTS_PER_SOL
      );
      const transferIx = SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: vault,
        lamports: opts.preFundVaultLamports,
      });
      const tx = new anchor.web3.Transaction().add(transferIx);
      await anchor.web3.sendAndConfirmTransaction(provider.connection, tx, [
        funder,
      ]);
    }
    return { members, multisig, vault };
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

  function buildSolTransferMessage(
    vault: PublicKey,
    recipient: PublicKey,
    lamports: number
  ) {
    const data = Buffer.alloc(12);
    data.writeUInt32LE(2, 0);
    data.writeBigUInt64LE(BigInt(lamports), 4);
    return {
      numSigners: 1,
      numWritableSigners: 1,
      numWritableNonSigners: 1,
      accountKeys: [vault, recipient, SystemProgram.programId],
      instructions: [
        {
          programIdIndex: 2,
          accountIndexes: Buffer.from([0, 1]),
          data,
        },
      ],
      addressTableLookups: [] as any[],
    };
  }

  /** Walk through create → approve(threshold) → execute. Returns proposal PDA + index. */
  async function createApproveExecute(opts: {
    members: Keypair[];
    multisig: PublicKey;
    vault: PublicKey;
    transferLamports: number;
  }): Promise<{ pda: PublicKey; index: bigint; recipient: Keypair }> {
    const recipient = Keypair.generate();
    const message = buildSolTransferMessage(
      opts.vault,
      recipient.publicKey,
      opts.transferLamports
    );
    const { pda, index } = await nextTransactionPda(opts.multisig);
    await program.methods
      .createTransaction(0, message as any)
      .accountsPartial({
        multisig: opts.multisig,
        transaction: pda,
        creator: opts.members[0].publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([opts.members[0]])
      .rpc();
    for (const m of opts.members.slice(0, 2)) {
      await program.methods
        .approveTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig: opts.multisig,
          transaction: pda,
          member: m.publicKey,
        })
        .signers([m])
        .rpc();
    }
    await program.methods
      .executeTransaction(new anchor.BN(index.toString()))
      .accountsPartial({
        multisig: opts.multisig,
        transaction: pda,
        executor: opts.members[0].publicKey,
      })
      .remainingAccounts([
        { pubkey: opts.vault, isSigner: false, isWritable: true },
        { pubkey: recipient.publicKey, isSigner: false, isWritable: true },
        {
          pubkey: SystemProgram.programId,
          isSigner: false,
          isWritable: false,
        },
      ])
      .signers([opts.members[0]])
      .rpc();
    return { pda, index, recipient };
  }

  it("closes an executed proposal and refunds rent to the creator", async () => {
    const { members, multisig, vault } = await setupMultisig({
      memberCount: 3,
      threshold: 2,
      preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
    });
    const { pda, index } = await createApproveExecute({
      members,
      multisig,
      vault,
      transferLamports: 0.01 * LAMPORTS_PER_SOL,
    });

    // Sanity — proposal exists.
    const acc = await provider.connection.getAccountInfo(pda);
    expect(acc).to.not.be.null;
    const rentLocked = acc!.lamports;
    expect(rentLocked).to.be.greaterThan(0);

    const balBefore = await provider.connection.getBalance(
      members[0].publicKey
    );

    await program.methods
      .closeTransaction(new anchor.BN(index.toString()))
      .accountsPartial({
        multisig,
        transaction: pda,
        creator: members[0].publicKey,
      })
      .signers([members[0]])
      .rpc();

    // Account is closed (sweeped to creator).
    const accAfter = await provider.connection.getAccountInfo(pda);
    expect(accAfter).to.be.null;

    // Creator's balance increased by ~rentLocked (minus tiny tx fee).
    const balAfter = await provider.connection.getBalance(members[0].publicKey);
    expect(balAfter - balBefore).to.be.greaterThan(rentLocked - 100_000);
  });

  it("rejects close when proposal has not been executed", async () => {
    const { members, multisig, vault } = await setupMultisig({
      memberCount: 3,
      threshold: 2,
      preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
    });
    const recipient = Keypair.generate();
    const message = buildSolTransferMessage(
      vault,
      recipient.publicKey,
      0.01 * LAMPORTS_PER_SOL
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

    let threw = false;
    try {
      await program.methods
        .closeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[0].publicKey,
        })
        .signers([members[0]])
        .rpc();
    } catch (e) {
      threw = true;
      expect(String(e)).to.match(/NotExecuted|not yet executed/i);
    }
    expect(threw).to.equal(true);
  });

  it("rejects close by a non-creator member", async () => {
    const { members, multisig, vault } = await setupMultisig({
      memberCount: 3,
      threshold: 2,
      preFundVaultLamports: 0.5 * LAMPORTS_PER_SOL,
    });
    const { pda, index } = await createApproveExecute({
      members,
      multisig,
      vault,
      transferLamports: 0.01 * LAMPORTS_PER_SOL,
    });

    let threw = false;
    try {
      await program.methods
        .closeTransaction(new anchor.BN(index.toString()))
        .accountsPartial({
          multisig,
          transaction: pda,
          creator: members[1].publicKey, // not the original creator
        })
        .signers([members[1]])
        .rpc();
    } catch (e) {
      threw = true;
      expect(String(e)).to.match(/UnauthorizedCloser|original creator/i);
    }
    expect(threw).to.equal(true);
  });
});
