use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::sysvar::instructions::{self, load_instruction_at_checked};

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

    /// Derive the vault address for given members, threshold, and vault_index.
    /// Vaults are SystemProgram-owned PDAs (no data) where funds live.
    /// Customer-facing: this is the address users send SOL/SPL tokens TO.
    pub fn derive_vault_address(
        _ctx: Context<DeriveAddress>,
        members: Vec<Pubkey>,
        threshold: u8,
        vault_index: u8,
    ) -> Result<Pubkey> {
        let (multisig_pda, _) = derive_multisig_pda(&members, threshold)?;
        let (vault_pda, _) = derive_vault_pda(&multisig_pda, vault_index);
        Ok(vault_pda)
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

        require!(members.len() <= MAX_MEMBERS, ErrorCode::TooManyMembers);

        // Sort members for deterministic PDA derivation
        let mut sorted_members = members.clone();
        sorted_members.sort();

        // Check for duplicates. saturating_sub guards against an empty members
        // list — that case is already rejected by the threshold check above
        // (threshold > 0 && threshold <= 0 is false), but defensive against
        // future refactors of the threshold check.
        for i in 0..sorted_members.len().saturating_sub(1) {
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

        msg!(
            "✅ Multisig initialized with {} members, threshold: {}",
            members.len(),
            threshold
        );
        msg!("✅ Multisig PDA: {}", ctx.accounts.multisig.key());

        Ok(())
    }

    /// Create a transaction proposal targeting a specific vault under the multisig.
    ///
    /// The proposal stores a V0-style transaction message that members vote on.
    /// Multiple proposals can be in flight without colliding because the
    /// multisig.transaction_index counter is incremented atomically here at
    /// create time (not at execute).
    ///
    /// Convention: `account_keys[0]` MUST be the vault PDA at `vault_index`.
    /// At execute time we sign for that PDA via invoke_signed using the cached
    /// `vault_bump` stored on the proposal.
    pub fn create_transaction(
        ctx: Context<CreateTransaction>,
        vault_index: u8,
        message: TransactionMessage,
    ) -> Result<()> {
        let multisig_key = ctx.accounts.multisig.key();
        let creator_key = ctx.accounts.creator.key();
        let multisig = &mut ctx.accounts.multisig;

        // Verify creator is a member.
        require!(
            multisig.members.contains(&creator_key),
            ErrorCode::UnauthorizedMember
        );

        // Compute the expected vault PDA + bump for this vault_index.
        let (expected_vault_pda, vault_bump) = derive_vault_pda(&multisig_key, vault_index);

        // Validate message structure.
        require!(!message.account_keys.is_empty(), ErrorCode::InvalidMessage);
        require!(
            message.account_keys.len() <= MAX_TX_ACCOUNT_KEYS,
            ErrorCode::InvalidMessage
        );
        require!(!message.instructions.is_empty(), ErrorCode::InvalidMessage);
        require!(
            message.instructions.len() <= MAX_TX_INSTRUCTIONS,
            ErrorCode::InvalidMessage
        );
        // Signer counts must be consistent.
        require!(
            (message.num_signers as usize) <= message.account_keys.len(),
            ErrorCode::InvalidMessage
        );
        require!(
            message.num_writable_signers <= message.num_signers,
            ErrorCode::InvalidMessage
        );
        let non_signer_count = message.account_keys.len() - message.num_signers as usize;
        require!(
            (message.num_writable_non_signers as usize) <= non_signer_count,
            ErrorCode::InvalidMessage
        );
        // The vault PDA must be the first signer (index 0). Any instruction
        // that moves vault funds references index 0; we sign for it via PDA
        // using the vault's seeds at execute time.
        require!(message.num_signers >= 1, ErrorCode::InvalidMessage);
        require_keys_eq!(
            message.account_keys[0],
            expected_vault_pda,
            ErrorCode::InvalidMessage
        );

        // Detect duplicate account_keys (wasteful and likely a client bug).
        for i in 0..message.account_keys.len() {
            for j in (i + 1)..message.account_keys.len() {
                require!(
                    message.account_keys[i] != message.account_keys[j],
                    ErrorCode::InvalidMessage
                );
            }
        }

        // Per-instruction Vec bounds (so we fail with a clean error before
        // the borsh write would fail when the account was over-allocated).
        for ix in &message.instructions {
            require!(
                ix.account_indexes.len() <= MAX_INSTRUCTION_ACCOUNTS,
                ErrorCode::InvalidMessage
            );
            require!(
                ix.data.len() <= MAX_INSTRUCTION_DATA_LEN,
                ErrorCode::InvalidMessage
            );
        }

        // Per-ALT-lookup Vec bounds.
        require!(
            message.address_table_lookups.len() <= MAX_ADDRESS_TABLE_LOOKUPS,
            ErrorCode::InvalidMessage
        );
        for lookup in &message.address_table_lookups {
            require!(
                lookup.writable_indexes.len() <= MAX_INDEXES_PER_LOOKUP,
                ErrorCode::InvalidMessage
            );
            require!(
                lookup.readonly_indexes.len() <= MAX_INDEXES_PER_LOOKUP,
                ErrorCode::InvalidMessage
            );
        }

        // Validate that all instruction indexes are within the combined account list.
        let total_alt_writable: usize = message
            .address_table_lookups
            .iter()
            .map(|l| l.writable_indexes.len())
            .sum();
        let total_alt_readonly: usize = message
            .address_table_lookups
            .iter()
            .map(|l| l.readonly_indexes.len())
            .sum();
        let combined_count = message.account_keys.len() + total_alt_writable + total_alt_readonly;
        // Solana's runtime caps total accounts per tx at 256 (u8 index space).
        require!(
            combined_count <= MAX_COMBINED_ACCOUNTS,
            ErrorCode::InvalidMessage
        );
        for ix in &message.instructions {
            // Program cannot be the multisig PDA (index 0) — it's a data account,
            // not a program. Defensive; runtime would reject otherwise.
            require!(ix.program_id_index >= 1, ErrorCode::InvalidMessage);
            require!(
                (ix.program_id_index as usize) < combined_count,
                ErrorCode::InvalidMessage
            );
            for idx in &ix.account_indexes {
                require!((*idx as usize) < combined_count, ErrorCode::InvalidMessage);
            }
        }

        // Atomically claim the next transaction index.
        let new_index = multisig
            .transaction_index
            .checked_add(1)
            .ok_or(ErrorCode::TransactionIndexOverflow)?;
        multisig.transaction_index = new_index;

        // Initialize the proposal.
        let transaction = &mut ctx.accounts.transaction;
        transaction.multisig = multisig_key;
        transaction.transaction_index = new_index;
        transaction.creator = creator_key;
        transaction.bump = ctx.bumps.transaction;
        transaction.vault_index = vault_index;
        transaction.vault_bump = vault_bump;
        transaction.executed = false;
        transaction.approvals = vec![];
        transaction.message = message;

        msg!(
            "Transaction {} created by {} targeting vault {}",
            new_index,
            creator_key,
            vault_index
        );

        Ok(())
    }

    /// Approve a transaction proposal. Each member can approve once.
    pub fn approve_transaction(
        ctx: Context<ApproveTransaction>,
        transaction_index: u64,
    ) -> Result<()> {
        let multisig = &ctx.accounts.multisig;
        let transaction = &mut ctx.accounts.transaction;

        // Verify transaction belongs to this multisig.
        require_keys_eq!(
            transaction.multisig,
            multisig.key(),
            ErrorCode::InvalidTransaction
        );

        // Verify transaction index matches.
        require_eq!(
            transaction.transaction_index,
            transaction_index,
            ErrorCode::InvalidTransactionIndex
        );

        // Verify not already executed.
        require!(!transaction.executed, ErrorCode::AlreadyExecuted);

        // Verify signer is a member.
        require!(
            multisig.members.contains(&ctx.accounts.member.key()),
            ErrorCode::UnauthorizedMember
        );

        // Check if already approved.
        require!(
            !transaction.approvals.contains(&ctx.accounts.member.key()),
            ErrorCode::AlreadyApproved
        );

        // Add approval.
        transaction.approvals.push(ctx.accounts.member.key());

        msg!(
            "Transaction {} approved by {} ({}/{})",
            transaction_index,
            ctx.accounts.member.key(),
            transaction.approvals.len(),
            multisig.threshold
        );

        Ok(())
    }

    /// Execute a transaction once threshold is reached.
    ///
    /// CPIs each compiled instruction with the multisig PDA as the signer
    /// (via invoke_signed). Resolves account_indexes against the combined
    /// account list (static account_keys + ALT-loaded accounts).
    ///
    /// `remaining_accounts` is expected in the following order, matching
    /// Solana's V0 transaction loading convention:
    ///   1. All static accounts in `message.account_keys` order
    ///   2. All ALT-loaded WRITABLE accounts in lookup order
    ///      (lookup 0 writable_indexes in order, then lookup 1, ...)
    ///   3. All ALT-loaded READONLY accounts in lookup order
    ///   4. Optional: the program_id accounts (if not already covered above)
    ///
    /// The client MUST construct the outer execute_transaction tx as a V0
    /// transaction with ALT lookups so the runtime resolves the addresses
    /// before our program runs. Our program only sees the resolved AccountInfos.
    pub fn execute_transaction<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteTransaction<'info>>,
        transaction_index: u64,
    ) -> Result<()> {
        // Validate first (immutable read), then mark executed (mutable),
        // then run CPIs. Marking executed BEFORE CPIs prevents re-entrancy
        // via a malicious proposal CPI'ing back into execute_transaction.
        // Solana auto-reverts state changes if any CPI fails, so this is safe.
        {
            let multisig = &ctx.accounts.multisig;
            let transaction = &ctx.accounts.transaction;

            require_keys_eq!(
                transaction.multisig,
                multisig.key(),
                ErrorCode::InvalidTransaction
            );
            require_eq!(
                transaction.transaction_index,
                transaction_index,
                ErrorCode::InvalidTransactionIndex
            );
            require!(!transaction.executed, ErrorCode::AlreadyExecuted);
            require!(
                transaction.approvals.len() >= multisig.threshold as usize,
                ErrorCode::InsufficientApprovals
            );
        }

        // Mark executed BEFORE CPIs (re-entrancy guard) — and force the write
        // to the on-chain data so a re-entrant CPI sees it. Anchor's Account<T>
        // caches the deserialized struct in memory and only flushes to the
        // underlying account at function exit. Without this manual exit() call,
        // a CPI calling back into execute_transaction would read stale data
        // (executed=false) and the guard would be bypassed.
        ctx.accounts.transaction.executed = true;
        ctx.accounts.transaction.exit(ctx.program_id)?;

        let multisig = &ctx.accounts.multisig;
        let transaction = &ctx.accounts.transaction;

        // ============================================================
        // Build the resolved account list:
        //   [ static_keys ] + [ ALT writable loaded ] + [ ALT readonly loaded ]
        // ============================================================
        let message = &transaction.message;
        let static_count = message.account_keys.len();
        let alt_writable_total: usize = message
            .address_table_lookups
            .iter()
            .map(|l| l.writable_indexes.len())
            .sum();
        let alt_readonly_total: usize = message
            .address_table_lookups
            .iter()
            .map(|l| l.readonly_indexes.len())
            .sum();
        let combined_count = static_count + alt_writable_total + alt_readonly_total;

        // Defensive: enforce Solana's u8 index cap at execute time too.
        require!(
            combined_count <= MAX_COMBINED_ACCOUNTS,
            ErrorCode::InvalidMessage
        );

        // remaining_accounts must contain at least all the resolved accounts.
        // The client may also append extra accounts (e.g. program_ids if not
        // already in the combined list). We require at least combined_count.
        let remaining = ctx.remaining_accounts;
        require!(
            remaining.len() >= combined_count,
            ErrorCode::InsufficientRemainingAccounts
        );

        // Build the resolved Pubkey list for the combined account space.
        // Static keys come from the stored message; ALT-loaded keys come from
        // the corresponding remaining_accounts (positional, runtime-validated).
        let mut combined_pubkeys: Vec<Pubkey> = Vec::with_capacity(combined_count);
        // Static section: must match remaining[i] exactly.
        for (i, expected_key) in message.account_keys.iter().enumerate() {
            require_keys_eq!(
                remaining[i].key(),
                *expected_key,
                ErrorCode::AccountMismatch
            );
            combined_pubkeys.push(*expected_key);
        }
        // ALT-loaded section: trust the client. The runtime already validated
        // the V0 outer tx's ALT contents against each ALT account.
        for acc in &remaining[static_count..combined_count] {
            combined_pubkeys.push(acc.key());
        }

        // ============================================================
        // PDA signer seeds for the VAULT (not the multisig).
        // The vault PDA is system-owned with no data, so SystemProgram::transfer
        // works with vault as source. We sign for vault via invoke_signed using
        // the vault_index + vault_bump cached on the proposal at create time.
        // ============================================================
        let multisig_key = multisig.key();
        let vault_index_byte = [transaction.vault_index];
        let vault_bump_byte = [transaction.vault_bump];
        let signer_seeds: &[&[&[u8]]] = &[&[
            VAULT_PDA_SEED,
            multisig_key.as_ref(),
            &vault_index_byte,
            &vault_bump_byte,
        ]];

        // Cached header values for is_signer / is_writable computation.
        let num_signers = message.num_signers as usize;
        let num_writable_signers = message.num_writable_signers as usize;
        let num_writable_non_signers = message.num_writable_non_signers as usize;
        let static_writable_end = num_signers + num_writable_non_signers;
        let alt_writable_end = static_count + alt_writable_total;
        let multisig_info = ctx.accounts.multisig.to_account_info();

        // ============================================================
        // Iterate compiled instructions and CPI each one.
        // ============================================================
        for (ix_index, compiled) in message.instructions.iter().enumerate() {
            msg!(
                "Executing instruction {} of {}",
                ix_index + 1,
                message.instructions.len()
            );

            let program_id_index = compiled.program_id_index as usize;
            require!(program_id_index < combined_count, ErrorCode::InvalidMessage);
            let program_id = combined_pubkeys[program_id_index];

            // Build AccountMetas + AccountInfos for the CPI.
            let mut account_metas: Vec<AccountMeta> =
                Vec::with_capacity(compiled.account_indexes.len());
            let mut account_infos: Vec<AccountInfo<'info>> =
                Vec::with_capacity(compiled.account_indexes.len() + 1);

            for &raw_index in &compiled.account_indexes {
                let i = raw_index as usize;
                require!(i < combined_count, ErrorCode::InvalidMessage);
                let pubkey = combined_pubkeys[i];

                // is_signer: any of the first num_signers static accounts.
                let is_signer = i < num_signers;
                // is_writable: depends on which section the index falls in.
                let is_writable = if i < num_writable_signers {
                    true // writable signer
                } else if i < num_signers {
                    false // readonly signer
                } else if i < static_writable_end {
                    true // writable non-signer (static)
                } else if i < static_count {
                    false // readonly non-signer (static)
                } else if i < alt_writable_end {
                    true // ALT-loaded writable
                } else {
                    false // ALT-loaded readonly
                };

                account_metas.push(if is_writable {
                    AccountMeta::new(pubkey, is_signer)
                } else {
                    AccountMeta::new_readonly(pubkey, is_signer)
                });

                // Pick the matching AccountInfo. For static accounts use the
                // positional remaining_accounts entry; for the multisig PDA
                // use the ctx-provided info to keep Anchor happy.
                let info = if pubkey == multisig_key {
                    multisig_info.clone()
                } else {
                    remaining[i].clone()
                };
                account_infos.push(info);
            }

            // Append the program account for the CPI. Find it in remaining
            // accounts (positional in combined list, or anywhere after if the
            // client appended extras).
            let program_info = if program_id == multisig_key {
                multisig_info.clone()
            } else if program_id_index < remaining.len() {
                remaining[program_id_index].clone()
            } else {
                return err!(ErrorCode::InvalidMessage);
            };
            account_infos.push(program_info);

            let instruction = Instruction {
                program_id,
                accounts: account_metas,
                data: compiled.data.clone(),
            };

            invoke_signed(&instruction, &account_infos, signer_seeds).map_err(|e| {
                msg!("CPI execution failed at ix {}: {:?}", ix_index, e);
                ErrorCode::CpiExecutionFailed
            })?;

            msg!("✅ Instruction {} executed successfully", ix_index + 1);
        }

        // executed=true was set BEFORE the CPI loop (re-entrancy guard).
        // If any CPI failed above we'd have returned an error and Solana
        // would have auto-reverted that write.
        msg!(
            "✅ Transaction {} fully executed with {} approvals",
            transaction_index,
            transaction.approvals.len()
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
    let sig_ix_index = u16::from_le_bytes([ix_data[4], ix_data[5]]);
    let pubkey_offset = u16::from_le_bytes([ix_data[6], ix_data[7]]) as usize;
    let pubkey_ix_index = u16::from_le_bytes([ix_data[8], ix_data[9]]);
    let msg_offset = u16::from_le_bytes([ix_data[10], ix_data[11]]) as usize;
    let msg_size = u16::from_le_bytes([ix_data[12], ix_data[13]]) as usize;
    let msg_ix_index = u16::from_le_bytes([ix_data[14], ix_data[15]]);

    // CRITICAL: each instruction_index must be 0xFFFF ("current instruction").
    // Otherwise the Ed25519 program reads sig/pubkey/message from a DIFFERENT
    // instruction's data, while our byte-level checks below validate the
    // current ix's data — the two verifications would operate on independent
    // data, allowing signature forgery: an attacker could replay a Solana
    // signature member1 made for ANY message, rebound to our canonical init
    // message via offset/index manipulation.
    require!(
        sig_ix_index == u16::MAX && pubkey_ix_index == u16::MAX && msg_ix_index == u16::MAX,
        ErrorCode::InvalidSignature
    );

    // Verify the signature bytes match
    require!(
        ix_data.len() >= sig_offset + 64,
        ErrorCode::InvalidSignature
    );
    let ix_signature = &ix_data[sig_offset..sig_offset + 64];
    require!(ix_signature == signature, ErrorCode::InvalidSignature);

    // Verify the public key bytes match
    require!(
        ix_data.len() >= pubkey_offset + 32,
        ErrorCode::InvalidSignature
    );
    let ix_pubkey = &ix_data[pubkey_offset..pubkey_offset + 32];
    require!(ix_pubkey == pubkey, ErrorCode::InvalidSignature);

    // Verify the message bytes match
    require!(
        ix_data.len() >= msg_offset + msg_size,
        ErrorCode::InvalidSignature
    );
    let ix_message = &ix_data[msg_offset..msg_offset + msg_size];
    require!(ix_message == message, ErrorCode::InvalidSignature);

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
///
/// Stores a compact, V0-style transaction message that members vote on.
/// Account keys are listed once in `message.account_keys` and referenced
/// by 1-byte index in compiled instructions, providing big storage savings
/// for proposals that touch many accounts (e.g. Jupiter swaps).
#[account]
#[derive(InitSpace)]
pub struct VaultTransaction {
    /// Multisig this transaction belongs to.
    pub multisig: Pubkey,

    /// Transaction index (matches multisig.transaction_index counter at create time).
    pub transaction_index: u64,

    /// Member who created the proposal.
    pub creator: Pubkey,

    /// PDA bump.
    pub bump: u8,

    /// Which vault under the multisig this proposal targets. The vault PDA
    /// at this index is the canonical signer for inner instructions (typically
    /// `account_keys[0]` in the message).
    pub vault_index: u8,

    /// Cached bump for the vault PDA. Avoids the find_program_address cost at
    /// execute time.
    pub vault_bump: u8,

    /// Whether transaction has been executed.
    pub executed: bool,

    /// Members who have approved.
    #[max_len(MAX_MEMBERS)]
    pub approvals: Vec<Pubkey>,

    /// The compact V0-style transaction message.
    pub message: TransactionMessage,
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

/// V0-style transaction message stored in a VaultTransaction.
///
/// Mirrors Solana's MessageV0 but omits recent_blockhash (re-signed at execute)
/// and fee_payer (the multisig PDA implicitly signs via invoke_signed).
///
/// Account ordering convention (matches Solana runtime):
///   account_keys = [
///     0..num_writable_signers           : writable signers (vault PDA at 0),
///     num_writable_signers..num_signers : readonly signers,
///     num_signers..num_signers+num_writable_non_signers : writable non-signers,
///     ...                               : readonly non-signers,
///   ]
/// Then ALT-loaded accounts append in the order:
///   [ all writable from address_table_lookups, all readonly from address_table_lookups ]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct TransactionMessage {
    /// Total signer count in account_keys.
    pub num_signers: u8,

    /// Number of writable signers (writable signers come first in account_keys).
    pub num_writable_signers: u8,

    /// Number of writable non-signers in account_keys (after the signers block).
    pub num_writable_non_signers: u8,

    /// Static account keys. By convention, the multisig PDA must be at index 0
    /// as the canonical writable signer.
    #[max_len(MAX_TX_ACCOUNT_KEYS)]
    pub account_keys: Vec<Pubkey>,

    /// Compiled instructions referencing accounts by 1-byte index.
    #[max_len(MAX_TX_INSTRUCTIONS)]
    pub instructions: Vec<CompiledInstruction>,

    /// Address Lookup Table references for compactly referencing many accounts.
    #[max_len(MAX_ADDRESS_TABLE_LOOKUPS)]
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}

/// A compiled instruction. Accounts and program are referenced by index into
/// the combined account list (static account_keys + ALT-loaded accounts).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct CompiledInstruction {
    /// Index of the program in the combined account list.
    pub program_id_index: u8,

    /// Indices of the instruction's accounts in the combined list.
    #[max_len(MAX_INSTRUCTION_ACCOUNTS)]
    pub account_indexes: Vec<u8>,

    /// Instruction data.
    #[max_len(MAX_INSTRUCTION_DATA_LEN)]
    pub data: Vec<u8>,
}

/// Reference to an Address Lookup Table for compactly loading many accounts.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct MessageAddressTableLookup {
    /// The on-chain ALT account address.
    pub account_key: Pubkey,

    /// Indices into the ALT pointing to writable accounts to load.
    #[max_len(MAX_INDEXES_PER_LOOKUP)]
    pub writable_indexes: Vec<u8>,

    /// Indices into the ALT pointing to readonly accounts to load.
    #[max_len(MAX_INDEXES_PER_LOOKUP)]
    pub readonly_indexes: Vec<u8>,
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
        payer = creator,
        space = 8 + VaultTransaction::INIT_SPACE,
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &(multisig.transaction_index + 1).to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, VaultTransaction>,

    #[account(mut)]
    pub creator: Signer<'info>,

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
    pub transaction: Account<'info, VaultTransaction>,

    pub member: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(transaction_index: u64)]
pub struct ExecuteTransaction<'info> {
    /// Read-only — execute_transaction never writes to multisig fields. Keeping
    /// this immutable prevents Anchor's auto-exit from re-serializing the
    /// cached struct at function end, which would otherwise overwrite any
    /// mutations made by recursive CPIs (e.g. a malicious proposal CPI'ing
    /// into create_transaction). Side benefit: blocks recursive
    /// create_transaction calls entirely (their constraint requires the outer
    /// tx to mark multisig writable, which conflicts with this immutability).
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
    pub transaction: Account<'info, VaultTransaction>,

    pub executor: Signer<'info>,
}

// ============================================================================
// Helper Functions - Phase 1 Core Logic
// ============================================================================

/// Derive multisig PDA from members and threshold
/// CRITICAL: NO PRIVATE KEY GENERATION - only PDA derivation
/// This is what makes it truly self-initiating and secure
pub fn derive_multisig_pda(members: &[Pubkey], threshold: u8) -> Result<(Pubkey, u8)> {
    let sorted_members = sort_members(members);
    let member_hash = hash_members(&sorted_members);

    let (pda, bump) =
        Pubkey::find_program_address(&[b"multisig", &member_hash[..8], &[threshold]], &crate::ID);

    Ok((pda, bump))
}

/// Derive a vault PDA owned by SystemProgram (no data) for the given multisig
/// and vault_index. Each multisig can have up to 256 vaults (vault_index = 0..255).
/// The vault holds SOL + SPL token accounts; SystemProgram::transfer from a vault
/// works because it's system-owned with empty data.
pub fn derive_vault_pda(multisig: &Pubkey, vault_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[VAULT_PDA_SEED, multisig.as_ref(), &[vault_index]],
        &crate::ID,
    )
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
pub const MAX_MEMBERS: usize = 20;

/// Maximum number of static account keys per transaction message.
/// These are the accounts referenced directly in the proposal (not via ALT).
pub const MAX_TX_ACCOUNT_KEYS: usize = 32;

/// Maximum number of instructions per transaction proposal.
pub const MAX_TX_INSTRUCTIONS: usize = 16;

/// Maximum number of account references per instruction.
/// Each reference is a 1-byte index into the combined account list
/// (static keys + ALT-loaded writable + ALT-loaded readonly).
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 64;

/// Maximum instruction data byte length.
pub const MAX_INSTRUCTION_DATA_LEN: usize = 1024;

/// Maximum number of Address Lookup Tables referenced by a proposal.
pub const MAX_ADDRESS_TABLE_LOOKUPS: usize = 4;

/// Maximum number of indexes per ALT lookup (writable and readonly each).
///
/// Tuned together with MAX_TX_ACCOUNT_KEYS and MAX_ADDRESS_TABLE_LOOKUPS so
/// that the maximum combined account count never exceeds Solana's 256-account
/// per-tx cap (u8 index space).
///   max_combined = MAX_TX_ACCOUNT_KEYS
///                + MAX_ADDRESS_TABLE_LOOKUPS * 2 * MAX_INDEXES_PER_LOOKUP
///                = 32 + 4 * 2 * 28 = 256
pub const MAX_INDEXES_PER_LOOKUP: usize = 28;

/// Solana hard cap on accounts per transaction (u8 index space).
pub const MAX_COMBINED_ACCOUNTS: usize = 256;

/// PDA seed prefix for vault accounts. Vaults are system-owned PDAs that
/// hold the actual funds (SOL + SPL tokens) governed by a multisig.
/// Derived as `[VAULT_PDA_SEED, multisig.key(), &[vault_index]]`.
pub const VAULT_PDA_SEED: &[u8] = b"vault";

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid threshold: must be > 0 and <= number of members")]
    InvalidThreshold,

    #[msg("Too many members: maximum is 20")]
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

    #[msg("Transaction message is malformed or violates structural invariants")]
    InvalidMessage,

    #[msg("Transaction index counter overflow")]
    TransactionIndexOverflow,

    #[msg("remaining_accounts has fewer entries than the proposal requires")]
    InsufficientRemainingAccounts,

    #[msg("Provided account does not match the static account_keys entry")]
    AccountMismatch,
}
