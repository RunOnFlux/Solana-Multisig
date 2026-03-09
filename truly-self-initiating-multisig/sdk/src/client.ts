import {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  TransactionInstruction,
  sendAndConfirmTransaction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import {
  SignatureData,
  InitializeResult,
  CreateTransactionResult,
  MultisigConfig,
  TransactionData,
} from "./types";
import {
  deriveMultisigAddress,
  createInitSignature,
  createInitializationMessage,
  sortMembers,
  validateConfig,
  verifySignature,
  createEd25519Instructions,
} from "./utils";

/**
 * Main SDK client for Truly Self-Initiating Multisig
 */
export class TrulySelfInitiatingMultisigClient {
  private connection: Connection;
  private program: Program;
  private programId: PublicKey;
  private provider: AnchorProvider;

  constructor(
    connection: Connection,
    programId: PublicKey,
    wallet?: Wallet
  ) {
    this.connection = connection;
    this.programId = programId;

    // Create provider
    this.provider = new AnchorProvider(
      connection,
      wallet || new Wallet(Keypair.generate()),
      { commitment: "confirmed" }
    );

    // Load program IDL
    const idl = require("../../target/idl/truly_self_initiating_multisig.json");
    this.program = new Program(idl, this.provider);
  }

  /**
   * Derive the deterministic multisig address
   * This can be called by anyone and will always return the same address
   * for the same configuration
   */
  deriveAddress(members: PublicKey[], threshold: number): PublicKey {
    validateConfig(members, threshold);
    const [address] = deriveMultisigAddress(members, threshold, this.programId);
    return address;
  }

  /**
   * Create an initialization signature (off-chain)
   * Each member must call this with their private key
   */
  createSignature(
    members: PublicKey[],
    threshold: number,
    memberKeypair: Keypair
  ): SignatureData {
    validateConfig(members, threshold);

    // Ensure the keypair is actually a member
    const sortedMembers = sortMembers(members);
    if (!sortedMembers.some(m => m.equals(memberKeypair.publicKey))) {
      throw new Error("Keypair is not a member of this multisig");
    }

    return createInitSignature(members, threshold, memberKeypair);
  }

  /**
   * Verify signatures (client-side validation before sending to chain)
   */
  verifySignatures(
    members: PublicKey[],
    threshold: number,
    signatures: SignatureData[]
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
      validateConfig(members, threshold);
    } catch (e) {
      errors.push(`Config validation failed: ${(e as Error).message}`);
      return { valid: false, errors };
    }

    // Check we have enough signatures
    if (signatures.length < threshold) {
      errors.push(`Insufficient signatures: need ${threshold}, got ${signatures.length}`);
    }

    // Verify each signature
    const sortedMembers = sortMembers(members);
    const seenSigners = new Set<string>();

    for (const sig of signatures) {
      // Check signer is a member
      if (!sortedMembers.some(m => m.equals(sig.signer))) {
        errors.push(`Signer ${sig.signer.toString()} is not a member`);
        continue;
      }

      // Check for duplicates
      const signerStr = sig.signer.toString();
      if (seenSigners.has(signerStr)) {
        errors.push(`Duplicate signature from ${signerStr}`);
        continue;
      }
      seenSigners.add(signerStr);

      // Verify signature
      if (!verifySignature(sig, members, threshold)) {
        errors.push(`Invalid signature from ${signerStr}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Initialize the multisig with collected signatures
   *
   * This sends a transaction containing:
   * 1. Ed25519 program instructions (one per signature) for on-chain verification
   * 2. The initialize_multisig instruction
   *
   * The Ed25519 program verifies each signature, and our program reads these
   * via the Instructions Sysvar to confirm verification.
   */
  async initialize(
    members: PublicKey[],
    threshold: number,
    signatures: SignatureData[],
    payer: Keypair
  ): Promise<InitializeResult> {
    validateConfig(members, threshold);

    // Client-side validation
    const validation = this.verifySignatures(members, threshold, signatures);
    if (!validation.valid) {
      throw new Error(`Signature validation failed:\n${validation.errors.join("\n")}`);
    }

    // Derive multisig address
    const sortedMembers = sortMembers(members);
    const [multisigAddress, bump] = deriveMultisigAddress(
      sortedMembers,
      threshold,
      this.programId
    );

    // Create Ed25519 verification instructions (must come BEFORE initialize)
    const ed25519Instructions = createEd25519Instructions(
      members,
      threshold,
      signatures
    );

    // Convert signatures to the format expected by the program
    const signaturesForProgram = signatures.map(sig => ({
      signer: sig.signer,
      signature: Array.from(sig.signature),
      messageHash: Array.from(sig.messageHash),
    }));

    // Build the initialize instruction
    const initializeIx = await this.program.methods
      .initializeMultisig(sortedMembers, threshold, signaturesForProgram)
      .accounts({
        multisig: multisigAddress,
        payer: payer.publicKey,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    // Build transaction with Ed25519 instructions FIRST, then initialize
    const transaction = new Transaction();

    // Add Ed25519 verification instructions
    for (const ix of ed25519Instructions) {
      transaction.add(ix);
    }

    // Add the initialize instruction
    transaction.add(initializeIx);

    // Send and confirm transaction
    const txSignature = await sendAndConfirmTransaction(
      this.connection,
      transaction,
      [payer],
      { commitment: "confirmed" }
    );

    return {
      signature: txSignature,
      multisigAddress,
      bump,
    };
  }

  /**
   * Pre-fund a multisig address before initialization
   * This demonstrates that funds can be sent to the deterministic address
   * before the multisig is initialized on-chain
   */
  async preFund(
    address: PublicKey,
    amount: number,
    funder: Keypair
  ): Promise<string> {
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: address,
        lamports: amount,
      })
    );

    const signature = await sendAndConfirmTransaction(
      this.connection,
      tx,
      [funder],
      { commitment: "confirmed" }
    );

    return signature;
  }

  /**
   * Get multisig account data
   */
  async getMultisig(address: PublicKey): Promise<MultisigConfig | null> {
    try {
      const account = await (this.program.account as any).multisig.fetch(address);
      return {
        members: account.members as PublicKey[],
        threshold: account.threshold as number,
        transactionIndex: account.transactionIndex as bigint,
        isInitialized: account.isInitialized as boolean,
        bump: account.bump as number,
      };
    } catch (e) {
      return null;
    }
  }

  /**
   * Create a transaction proposal
   */
  async createTransaction(
    multisigAddress: PublicKey,
    instructions: TransactionInstruction[],
    creator: Keypair
  ): Promise<CreateTransactionResult> {
    // Get multisig data
    const multisig = await this.getMultisig(multisigAddress);
    if (!multisig) {
      throw new Error("Multisig not found");
    }

    // Derive transaction PDA
    const transactionIndex = multisig.transactionIndex + BigInt(1);
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    // Convert instructions to serializable format
    const serializableInstructions = instructions.map(ix => ({
      programId: ix.programId,
      accounts: ix.keys.map(k => ({
        pubkey: k.pubkey,
        isSigner: k.isSigner,
        isWritable: k.isWritable,
      })),
      data: Array.from(ix.data),
    }));

    // Create transaction
    const tx = await this.program.methods
      .createTransaction(serializableInstructions)
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        member: creator.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([creator])
      .rpc();

    return {
      signature: tx,
      transactionAddress,
      transactionIndex: transactionIndex,
    };
  }

  /**
   * Approve a transaction proposal
   */
  async approveTransaction(
    multisigAddress: PublicKey,
    transactionIndex: bigint,
    member: Keypair
  ): Promise<string> {
    // Derive transaction PDA
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    const tx = await this.program.methods
      .approveTransaction(new anchor.BN(transactionIndex.toString()))
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        member: member.publicKey,
      })
      .signers([member])
      .rpc();

    return tx;
  }

  /**
   * Execute an approved transaction
   */
  async executeTransaction(
    multisigAddress: PublicKey,
    transactionIndex: bigint,
    executor: Keypair,
    remainingAccounts?: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[]
  ): Promise<string> {
    // Derive transaction PDA
    const [transactionAddress] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("transaction"),
        multisigAddress.toBytes(),
        new anchor.BN(transactionIndex.toString()).toArrayLike(Buffer, "le", 8),
      ],
      this.programId
    );

    let txBuilder = this.program.methods
      .executeTransaction(new anchor.BN(transactionIndex.toString()))
      .accounts({
        multisig: multisigAddress,
        transaction: transactionAddress,
        executor: executor.publicKey,
      })
      .signers([executor]);

    // Add remaining accounts for CPI if provided
    if (remainingAccounts && remainingAccounts.length > 0) {
      txBuilder = txBuilder.remainingAccounts(remainingAccounts);
    }

    const tx = await txBuilder.rpc();

    return tx;
  }

  /**
   * Get transaction data
   */
  async getTransaction(address: PublicKey): Promise<TransactionData | null> {
    try {
      const account = await (this.program.account as any).transaction.fetch(address);
      return {
        multisig: account.multisig as PublicKey,
        index: account.transactionIndex as bigint,
        instructions: account.instructions as any[],
        approvers: account.approvals as PublicKey[],
        executed: account.executed as boolean,
      };
    } catch (e) {
      return null;
    }
  }
}
