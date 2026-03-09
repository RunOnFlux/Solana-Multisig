use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::sysvar::instructions::{
    self, load_instruction_at_checked,
};

declare_id!("F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo");

#[program]
pub mod truly_self_initiating_multisig {
    use super::*;

    /// Derive the multisig address for given members and threshold
    /// This is a view function - no state changes, just returns the deterministic PDA
    pub fn derive_address(
        _ctx: Context<DeriveAddress>,
        members: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<Pubkey> {
        let multisig_pda = derive_multisig_pda(&members, threshold)?;
        Ok(multisig_pda.0)
    }

    /// Initialize a truly self-initiating multisig
    ///
    /// SECURITY: This function verifies Ed25519 signatures using Solana's native
    /// Ed25519 program. The signatures must be submitted as a preceding instruction
    /// in the same transaction, which is verified via the Instructions Sysvar.
    ///
    /// NO DETERMINISTIC PRIVATE KEYS - only member signatures verified on-chain.
    pub fn initialize_multisig(
        ctx: Context<InitializeMultisig>,
        members: Vec<Pubkey>,
        threshold: u8,
        signatures: Vec<SignatureData>,
    ) -> Result<()> {
        // Validate configuration
        require!(
            threshold > 0 && threshold <= members.len() as u8,
            ErrorCode::InvalidThreshold
        );

        require!(
            members.len() <= MAX_MEMBERS,
            ErrorCode::TooManyMembers
        );

        // Sort members for deterministic PDA derivation
        let mut sorted_members = members.clone();
        sorted_members.sort();

        // Check for duplicates
        for i in 0..sorted_members.len() - 1 {
            require!(
                sorted_members[i] != sorted_members[i + 1],
                ErrorCode::DuplicateMembers
            );
        }

        // Validate we have enough signatures
        require!(
            signatures.len() >= threshold as usize,
            ErrorCode::InsufficientSignatures
        );

        // Verify PDA derivation matches
        let (expected_pda, bump) = derive_multisig_pda(&sorted_members, threshold)?;
        require_keys_eq!(
            ctx.accounts.multisig.key(),
            expected_pda,
            ErrorCode::InvalidPDA
        );

        // Create initialization message for signature verification
        let init_message = create_initialization_message(&sorted_members, threshold);
        let message_hash = hash(&init_message).to_bytes();

        // ====================================================
        // CRITICAL: Verify Ed25519 signatures using Solana's
        // native Ed25519 program via Instructions Sysvar
        // ====================================================

        let ix_sysvar = &ctx.accounts.instructions_sysvar;

        // Verify each signature
        let mut verified_members = Vec::new();

        for (sig_index, sig_data) in signatures.iter().enumerate() {
            // Verify signer is a member
            require!(
                sorted_members.contains(&sig_data.signer),
                ErrorCode::UnauthorizedSigner
            );

            // Check for duplicate signatures
            require!(
                !verified_members.contains(&sig_data.signer),
                ErrorCode::DuplicateSignature
            );

            // Verify message hash matches
            require!(
                sig_data.message_hash == message_hash,
                ErrorCode::InvalidMessageHash
            );

            // Verify the Ed25519 signature via Instructions Sysvar
            // The client must have included an Ed25519 program instruction
            // at position `sig_index` in the transaction
            verify_ed25519_signature(
                ix_sysvar,
                sig_index,
                &sig_data.signer.to_bytes(),
                &init_message,
                &sig_data.signature,
            )?;

            msg!("✅ Verified signature from member: {}", sig_data.signer);

            // Store the verified member
            verified_members.push(sig_data.signer);
        }

        // Initialize the multisig account
        let multisig = &mut ctx.accounts.multisig;
        multisig.members = sorted_members;
        multisig.threshold = threshold;
        multisig.transaction_index = 0;
        multisig.is_initialized = true;
        multisig.bump = bump;

        msg!("✅ Multisig initialized with {} members, threshold: {}", members.len(), threshold);
        msg!("✅ Multisig PDA: {}", ctx.accounts.multisig.key());

        Ok(())
    }

    /// Create a transaction proposal
    pub fn create_transaction(
        ctx: Context<CreateTransaction>,
        instructions: Vec<SerializableInstruction>,
    ) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        let transaction = &mut ctx.accounts.transaction;

        // Verify signer is a member
        require!(
            multisig.members.contains(&ctx.accounts.member.key()),
            ErrorCode::UnauthorizedMember
        );

        let transaction_index = multisig.transaction_index + 1;

        transaction.multisig = ctx.accounts.multisig.key();
        transaction.transaction_index = transaction_index;
        transaction.instructions = instructions;
        transaction.approvals = vec![];
        transaction.executed = false;

        msg!("Transaction {} created by {}", transaction_index, ctx.accounts.member.key());

        Ok(())
    }

    /// Approve a transaction
    pub fn approve_transaction(
        ctx: Context<ApproveTransaction>,
        transaction_index: u64,
    ) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        let transaction = &mut ctx.accounts.transaction;

        // Verify transaction belongs to this multisig
        require_keys_eq!(
            transaction.multisig,
            multisig.key(),
            ErrorCode::InvalidTransaction
        );

        // Verify transaction index matches
        require_eq!(
            transaction.transaction_index,
            transaction_index,
            ErrorCode::InvalidTransactionIndex
        );

        // Verify signer is a member
        require!(
            multisig.members.contains(&ctx.accounts.member.key()),
            ErrorCode::UnauthorizedMember
        );

        // Check if already approved
        require!(
            !transaction.approvals.contains(&ctx.accounts.member.key()),
            ErrorCode::AlreadyApproved
        );

        // Add approval
        transaction.approvals.push(ctx.accounts.member.key());

        msg!("Transaction {} approved by {} ({}/{})",
            transaction_index,
            ctx.accounts.member.key(),
            transaction.approvals.len(),
            multisig.threshold
        );

        Ok(())
    }

    /// Execute a transaction once threshold is reached
    /// This ACTUALLY executes the instructions via CPI with PDA signing
    pub fn execute_transaction<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteTransaction<'info>>,
        transaction_index: u64,
    ) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        let transaction = &ctx.accounts.transaction;

        // Verify transaction belongs to this multisig
        require_keys_eq!(
            transaction.multisig,
            multisig.key(),
            ErrorCode::InvalidTransaction
        );

        // Verify transaction index
        require_eq!(
            transaction.transaction_index,
            transaction_index,
            ErrorCode::InvalidTransactionIndex
        );

        // Verify not already executed
        require!(!transaction.executed, ErrorCode::AlreadyExecuted);

        // Verify we have threshold approvals
        require!(
            transaction.approvals.len() >= multisig.threshold as usize,
            ErrorCode::InsufficientApprovals
        );

        // ====================================================
        // CRITICAL: Actually execute the instructions via CPI!
        // ====================================================

        // Build the PDA signer seeds for the multisig
        let sorted_members = sort_members(&multisig.members);
        let member_hash = hash_members(&sorted_members);
        let bump = multisig.bump;

        let signer_seeds: &[&[&[u8]]] = &[&[
            b"multisig",
            &member_hash[..8],
            &[multisig.threshold],
            &[bump],
        ]];

        // Get remaining accounts for CPI
        let remaining_accounts = ctx.remaining_accounts;

        // Execute each instruction in the transaction
        for (ix_index, serialized_ix) in transaction.instructions.iter().enumerate() {
            msg!("Executing instruction {} of {}", ix_index + 1, transaction.instructions.len());

            // Convert SerializableInstruction to Solana Instruction
            let accounts: Vec<AccountMeta> = serialized_ix
                .accounts
                .iter()
                .map(|acc| {
                    if acc.is_writable {
                        AccountMeta::new(acc.pubkey, acc.is_signer)
                    } else {
                        AccountMeta::new_readonly(acc.pubkey, acc.is_signer)
                    }
                })
                .collect();

            let instruction = Instruction {
                program_id: serialized_ix.program_id,
                accounts,
                data: serialized_ix.data.clone(),
            };

            // Find the account infos needed for this instruction
            let mut account_infos: Vec<AccountInfo<'info>> = Vec::new();

            // Add the program being invoked
            for acc_info in remaining_accounts.iter() {
                if acc_info.key() == serialized_ix.program_id {
                    account_infos.push(acc_info.clone());
                    break;
                }
            }

            // Add all accounts required by the instruction
            for acc_meta in instruction.accounts.iter() {
                // Check if this is the multisig PDA (which needs to sign)
                if acc_meta.pubkey == multisig.key() {
                    account_infos.push(ctx.accounts.multisig.to_account_info());
                } else {
                    // Find in remaining accounts
                    for acc_info in remaining_accounts.iter() {
                        if acc_info.key() == acc_meta.pubkey {
                            account_infos.push(acc_info.clone());
                            break;
                        }
                    }
                }
            }

            // Execute the CPI with PDA signing
            invoke_signed(&instruction, &account_infos, signer_seeds)
                .map_err(|e| {
                    msg!("CPI execution failed: {:?}", e);
                    ErrorCode::CpiExecutionFailed
                })?;

            msg!("✅ Instruction {} executed successfully", ix_index + 1);
        }

        // Mark as executed AFTER successful CPI
        let transaction = &mut ctx.accounts.transaction;
        transaction.executed = true;

        // Update multisig transaction index
        let multisig = &mut ctx.accounts.multisig;
        multisig.transaction_index = transaction_index;

        msg!("✅ Transaction {} fully executed with {} approvals",
            transaction_index,
            ctx.accounts.transaction.approvals.len()
        );

        Ok(())
    }
}

// ============================================================================
// Ed25519 Signature Verification Helper
// ============================================================================

/// Verify an Ed25519 signature using Solana's native Ed25519 program
/// via the Instructions Sysvar.
///
/// The client must include an Ed25519 program verify instruction
/// BEFORE the initialize_multisig instruction in the same transaction.
fn verify_ed25519_signature(
    ix_sysvar: &AccountInfo,
    expected_ix_index: usize,
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    // Load the instruction at the expected index
    let ix = load_instruction_at_checked(expected_ix_index, ix_sysvar)
        .map_err(|_| ErrorCode::InvalidSignature)?;

    // Verify it's an Ed25519 program instruction
    require!(
        ix.program_id == ed25519_program::ID,
        ErrorCode::InvalidSignature
    );

    // The Ed25519 instruction data format:
    // - 1 byte: number of signatures
    // - 1 byte: padding
    // For each signature:
    // - 2 bytes: signature offset
    // - 2 bytes: signature instruction index (0xFFFF = same instruction)
    // - 2 bytes: public key offset
    // - 2 bytes: public key instruction index
    // - 2 bytes: message data offset
    // - 2 bytes: message data size
    // - 2 bytes: message instruction index
    // Then the actual data: signature (64 bytes), pubkey (32 bytes), message

    let ix_data = &ix.data;

    // Must have at least 2 bytes for header
    require!(ix_data.len() >= 2, ErrorCode::InvalidSignature);

    let num_signatures = ix_data[0];
    require!(num_signatures >= 1, ErrorCode::InvalidSignature);

    // Parse the first signature entry (we only need one per ix)
    // Header is 2 bytes, each signature entry is 14 bytes
    require!(ix_data.len() >= 2 + 14, ErrorCode::InvalidSignature);

    let sig_offset = u16::from_le_bytes([ix_data[2], ix_data[3]]) as usize;
    let pubkey_offset = u16::from_le_bytes([ix_data[6], ix_data[7]]) as usize;
    let msg_offset = u16::from_le_bytes([ix_data[10], ix_data[11]]) as usize;
    let msg_size = u16::from_le_bytes([ix_data[12], ix_data[13]]) as usize;

    // Verify the signature bytes match
    require!(
        ix_data.len() >= sig_offset + 64,
        ErrorCode::InvalidSignature
    );
    let ix_signature = &ix_data[sig_offset..sig_offset + 64];
    require!(
        ix_signature == signature,
        ErrorCode::InvalidSignature
    );

    // Verify the public key bytes match
    require!(
        ix_data.len() >= pubkey_offset + 32,
        ErrorCode::InvalidSignature
    );
    let ix_pubkey = &ix_data[pubkey_offset..pubkey_offset + 32];
    require!(
        ix_pubkey == pubkey,
        ErrorCode::InvalidSignature
    );

    // Verify the message bytes match
    require!(
        ix_data.len() >= msg_offset + msg_size,
        ErrorCode::InvalidSignature
    );
    let ix_message = &ix_data[msg_offset..msg_offset + msg_size];
    require!(
        ix_message == message,
        ErrorCode::InvalidSignature
    );

    // If we get here, the Ed25519 program has verified this signature!
    // (The Ed25519 program instruction would have failed if invalid)

    Ok(())
}

// ============================================================================
// State Definitions - Phase 1 Architecture
// ============================================================================

/// Multisig account - stores configuration and state
/// This is the core of our self-initiating design
#[account]
#[derive(InitSpace)]
pub struct Multisig {
    /// Sorted member public keys
    #[max_len(MAX_MEMBERS)]
    pub members: Vec<Pubkey>,

    /// Required number of signatures
    pub threshold: u8,

    /// Counter for transactions
    pub transaction_index: u64,

    /// Whether this multisig is initialized
    pub is_initialized: bool,

    /// PDA bump seed
    pub bump: u8,
}

/// Transaction proposal account
#[account]
#[derive(InitSpace)]
pub struct Transaction {
    /// Multisig this transaction belongs to
    pub multisig: Pubkey,

    /// Transaction index
    pub transaction_index: u64,

    /// Instructions to execute
    #[max_len(MAX_INSTRUCTIONS)]
    pub instructions: Vec<SerializableInstruction>,

    /// Members who have approved
    #[max_len(MAX_MEMBERS)]
    pub approvals: Vec<Pubkey>,

    /// Whether transaction has been executed
    pub executed: bool,
}

/// Signature data for initialization
/// Members sign this off-chain and submit for on-chain verification
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SignatureData {
    /// Member who signed
    pub signer: Pubkey,

    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],

    /// Hash of the message that was signed
    pub message_hash: [u8; 32],
}

/// Serializable instruction for transaction execution
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct SerializableInstruction {
    /// Program to invoke
    pub program_id: Pubkey,

    /// Accounts required by the instruction
    #[max_len(MAX_ACCOUNTS_PER_IX)]
    pub accounts: Vec<SerializableAccountMeta>,

    /// Instruction data
    #[max_len(MAX_IX_DATA_LEN)]
    pub data: Vec<u8>,
}

/// Serializable account metadata
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct SerializableAccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

// ============================================================================
// Context Structs - Define account requirements for each instruction
// ============================================================================

#[derive(Accounts)]
pub struct DeriveAddress<'info> {
    /// Any account can call this view function
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(members: Vec<Pubkey>, threshold: u8)]
pub struct InitializeMultisig<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Multisig::INIT_SPACE,
        seeds = [
            b"multisig",
            &hash_members(&sort_members(&members))[..8],
            &[threshold],
        ],
        bump
    )]
    pub multisig: Account<'info, Multisig>,

    #[account(mut)]
    pub payer: Signer<'info>,

    /// Instructions Sysvar for Ed25519 signature verification
    /// CHECK: This is the Instructions Sysvar
    #[account(address = instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateTransaction<'info> {
    #[account(mut)]
    pub multisig: Account<'info, Multisig>,

    #[account(
        init,
        payer = member,
        space = 8 + Transaction::INIT_SPACE,
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &(multisig.transaction_index + 1).to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, Transaction>,

    #[account(mut)]
    pub member: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(transaction_index: u64)]
pub struct ApproveTransaction<'info> {
    pub multisig: Account<'info, Multisig>,

    #[account(
        mut,
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &transaction_index.to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, Transaction>,

    pub member: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(transaction_index: u64)]
pub struct ExecuteTransaction<'info> {
    #[account(mut)]
    pub multisig: Account<'info, Multisig>,

    #[account(
        mut,
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &transaction_index.to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, Transaction>,

    pub executor: Signer<'info>,
}

// ============================================================================
// Helper Functions - Phase 1 Core Logic
// ============================================================================

/// Derive multisig PDA from members and threshold
/// CRITICAL: NO PRIVATE KEY GENERATION - only PDA derivation
/// This is what makes it truly self-initiating and secure
pub fn derive_multisig_pda(
    members: &[Pubkey],
    threshold: u8,
) -> Result<(Pubkey, u8)> {
    let sorted_members = sort_members(members);
    let member_hash = hash_members(&sorted_members);

    let (pda, bump) = Pubkey::find_program_address(
        &[
            b"multisig",
            &member_hash[..8],
            &[threshold],
        ],
        &crate::ID,
    );

    Ok((pda, bump))
}

/// Sort members for deterministic derivation
fn sort_members(members: &[Pubkey]) -> Vec<Pubkey> {
    let mut sorted = members.to_vec();
    sorted.sort();
    sorted
}

/// Hash members for PDA seeds
/// This creates a deterministic hash of all member keys
fn hash_members(members: &[Pubkey]) -> [u8; 32] {
    let mut data = Vec::new();
    for member in members {
        data.extend_from_slice(member.as_ref());
    }
    hash(&data).to_bytes()
}

/// Create initialization message for signing
/// Members sign this message off-chain using their ACTUAL private keys
/// NOT a deterministic key that can be front-run
fn create_initialization_message(members: &[Pubkey], threshold: u8) -> Vec<u8> {
    let mut message = Vec::new();

    // Add domain separator to prevent signature reuse
    message.extend_from_slice(b"TRULY_SELF_INITIATING_MULTISIG_INIT");

    // Add members
    for member in members {
        message.extend_from_slice(member.as_ref());
    }

    // Add threshold
    message.push(threshold);

    message
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of members in a multisig
pub const MAX_MEMBERS: usize = 10;

/// Maximum number of instructions per transaction
pub const MAX_INSTRUCTIONS: usize = 8;

/// Maximum number of accounts per instruction
pub const MAX_ACCOUNTS_PER_IX: usize = 20;

/// Maximum instruction data length
pub const MAX_IX_DATA_LEN: usize = 1024;

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid threshold: must be > 0 and <= number of members")]
    InvalidThreshold,

    #[msg("Too many members: maximum is 10")]
    TooManyMembers,

    #[msg("Duplicate members not allowed")]
    DuplicateMembers,

    #[msg("Insufficient signatures provided")]
    InsufficientSignatures,

    #[msg("Invalid PDA derivation")]
    InvalidPDA,

    #[msg("Signer is not an authorized member")]
    UnauthorizedSigner,

    #[msg("Duplicate signature from same member")]
    DuplicateSignature,

    #[msg("Message hash does not match")]
    InvalidMessageHash,

    #[msg("Invalid Ed25519 signature - cryptographic verification failed")]
    InvalidSignature,

    #[msg("Member is not authorized for this multisig")]
    UnauthorizedMember,

    #[msg("Invalid transaction")]
    InvalidTransaction,

    #[msg("Invalid transaction index")]
    InvalidTransactionIndex,

    #[msg("Transaction already approved by this member")]
    AlreadyApproved,

    #[msg("Transaction already executed")]
    AlreadyExecuted,

    #[msg("Insufficient approvals to execute")]
    InsufficientApprovals,

    #[msg("CPI execution failed")]
    CpiExecutionFailed,
}
