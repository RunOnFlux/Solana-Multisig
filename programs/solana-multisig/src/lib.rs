use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::sysvar::instructions::{self, load_instruction_at_checked};

declare_id!("CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "SSP Solana Multisig",
    project_url: "https://sspwallet.com",
    contacts: "email:tadeas@runonflux.com",
    policy: "Responsible disclosure: please report any security issues via email to tadeas@runonflux.com. Critical vulnerabilities affecting user funds will be acknowledged within 24 hours.",
    preferred_languages: "en"
}

/// Like `require!`, but logs a specific reason via `msg!` before returning.
/// Used for generic error codes (e.g., `InvalidMessage`) that cover many
/// failure modes — gives users an actionable debug message in tx logs without
/// growing the IDL with 15 separate error variants.
macro_rules! require_msg {
    ($cond:expr, $error:expr, $msg:literal) => {
        if !($cond) {
            msg!($msg);
            return Err(error!($error));
        }
    };
}

#[program]
pub mod solana_multisig {
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

    /// Initialize a self-initiating multisig.
    ///
    /// Members are passed via `remaining_accounts` (typically resolved from
    /// an Address Lookup Table the client set up beforehand) so they cost
    /// only ~1 byte each in the transaction instead of 32. This is what
    /// lets us fit "any 7-of-N" multisigs (single-sig mode) into Solana's
    /// 1232-byte transaction cap.
    ///
    /// `member_hash` is `sha256(sorted_members)` computed off-chain by the
    /// client and used to derive the multisig PDA. The function recomputes
    /// the hash from the actual `remaining_accounts` and rejects if it
    /// disagrees — this binds the PDA address to the on-chain stored
    /// member set.
    ///
    /// SECURITY: each member signs a fixed-size init message off-chain
    /// (`prefix || sha256(sorted_members) || threshold` — 53 bytes
    /// regardless of N). The SDK packs all signatures into a single
    /// Ed25519 native-program instruction at index 0 of the same tx; we
    /// read it via the Instructions Sysvar, confirm it verified OUR init
    /// message, and harvest the list of signers.
    ///
    /// NO DETERMINISTIC PRIVATE KEYS — only member signatures verified
    /// on-chain via the native Ed25519 program.
    pub fn initialize_multisig<'info>(
        ctx: Context<'_, '_, '_, 'info, InitializeMultisig<'info>>,
        member_hash: [u8; 32],
        threshold: u8,
    ) -> Result<()> {
        // Harvest members from remaining_accounts. The client typically
        // sources these from an ALT, but the program doesn't care — they
        // can also be passed as static accounts.
        let members: Vec<Pubkey> = ctx.remaining_accounts.iter().map(|a| a.key()).collect();

        require!(
            threshold > 0 && threshold <= members.len() as u8,
            ErrorCode::InvalidThreshold
        );
        require!(members.len() <= MAX_MEMBERS, ErrorCode::TooManyMembers);

        // Sort for deterministic PDA derivation. Dedup check uses adjacency
        // after sorting.
        let mut sorted_members = members.clone();
        sorted_members.sort();
        for i in 0..sorted_members.len().saturating_sub(1) {
            require!(
                sorted_members[i] != sorted_members[i + 1],
                ErrorCode::DuplicateMembers
            );
        }

        // Bind member_hash → sorted_members. Without this, a caller could
        // supply different remaining_accounts than the hash claims, and the
        // multisig would end up at a PDA that doesn't reflect its members.
        let actual_hash = hash_members(&sorted_members);
        require!(actual_hash == member_hash, ErrorCode::InvalidPDA);

        // Anchor's init constraint already validated the multisig account
        // is at the PDA derived from member_hash + threshold; combined with
        // actual_hash == member_hash, the PDA is bound to the members.

        // Verify Ed25519 signatures (program-side check that the Ed25519
        // ix verified OUR init message and return the signer list).
        let init_message = create_initialization_message(&sorted_members, threshold);
        let signers = verify_ed25519_batch(&ctx.accounts.instructions_sysvar, 0, &init_message)?;

        require!(
            signers.len() >= threshold as usize,
            ErrorCode::InsufficientSignatures
        );
        for (i, signer) in signers.iter().enumerate() {
            require!(
                sorted_members.contains(signer),
                ErrorCode::UnauthorizedSigner
            );
            for prior in &signers[..i] {
                require!(prior != signer, ErrorCode::DuplicateSignature);
            }
        }

        // Initialize the multisig account.
        let bump = ctx.bumps.multisig;
        let multisig = &mut ctx.accounts.multisig;
        multisig.members = sorted_members;
        multisig.threshold = threshold;
        multisig.transaction_index = 0;
        multisig.bump = bump;

        msg!(
            "✅ Multisig initialized: {} members, threshold {}, {} signatures verified",
            members.len(),
            threshold,
            signers.len()
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
        require_msg!(
            !message.account_keys.is_empty(),
            ErrorCode::InvalidMessage,
            "InvalidMessage: account_keys must not be empty"
        );
        require_msg!(
            message.account_keys.len() <= MAX_TX_ACCOUNT_KEYS,
            ErrorCode::InvalidMessage,
            "InvalidMessage: account_keys exceeds MAX_TX_ACCOUNT_KEYS"
        );
        require_msg!(
            !message.instructions.is_empty(),
            ErrorCode::InvalidMessage,
            "InvalidMessage: instructions must not be empty"
        );
        require_msg!(
            message.instructions.len() <= MAX_TX_INSTRUCTIONS,
            ErrorCode::InvalidMessage,
            "InvalidMessage: instructions exceeds MAX_TX_INSTRUCTIONS"
        );
        // Signer counts must be consistent.
        require_msg!(
            (message.num_signers as usize) <= message.account_keys.len(),
            ErrorCode::InvalidMessage,
            "InvalidMessage: num_signers > account_keys.len"
        );
        require_msg!(
            message.num_writable_signers <= message.num_signers,
            ErrorCode::InvalidMessage,
            "InvalidMessage: num_writable_signers > num_signers"
        );
        let non_signer_count = message.account_keys.len() - message.num_signers as usize;
        require_msg!(
            (message.num_writable_non_signers as usize) <= non_signer_count,
            ErrorCode::InvalidMessage,
            "InvalidMessage: num_writable_non_signers > non-signer slots"
        );
        // The vault PDA must be the first signer (index 0). Any instruction
        // that moves vault funds references index 0; we sign for it via PDA
        // using the vault's seeds at execute time.
        require_msg!(
            message.num_signers >= 1,
            ErrorCode::InvalidMessage,
            "InvalidMessage: num_signers must be >= 1 (vault must sign)"
        );
        require_msg!(
            message.account_keys[0] == expected_vault_pda,
            ErrorCode::InvalidMessage,
            "InvalidMessage: account_keys[0] must equal the vault PDA at vault_index"
        );

        // Detect duplicate account_keys (wasteful and likely a client bug).
        for i in 0..message.account_keys.len() {
            for j in (i + 1)..message.account_keys.len() {
                require_msg!(
                    message.account_keys[i] != message.account_keys[j],
                    ErrorCode::InvalidMessage,
                    "InvalidMessage: duplicate entry in account_keys"
                );
            }
        }

        // Per-instruction Vec bounds (so we fail with a clean error before
        // the borsh write would fail when the account was over-allocated).
        for ix in &message.instructions {
            require_msg!(
                ix.account_indexes.len() <= MAX_INSTRUCTION_ACCOUNTS,
                ErrorCode::InvalidMessage,
                "InvalidMessage: instruction account_indexes exceeds MAX_INSTRUCTION_ACCOUNTS"
            );
            require_msg!(
                ix.data.len() <= MAX_INSTRUCTION_DATA_LEN,
                ErrorCode::InvalidMessage,
                "InvalidMessage: instruction data exceeds MAX_INSTRUCTION_DATA_LEN"
            );
        }

        // ALT references INSIDE a proposal are not allowed.
        //
        // The proposer can include up to MAX_TX_ACCOUNT_KEYS pubkeys directly in
        // `account_keys` (resolved at create time). At execute time, the
        // executor is free to use ALTs in the *outer* V0 transaction to fit
        // those static pubkeys compactly — our equality check
        // (`remaining[i].key() == account_keys[i]`) catches any substitution
        // regardless of whether they came from the V0 outer's static section
        // or its ALT lookups.
        //
        // Allowing ALT references inside the proposal would mean trusting the
        // executor's choice of ALT at execute time: a malicious executor could
        // swap in a different ALT (with attacker-controlled addresses at the
        // same indexes), redirecting CPI destinations. The proposal storage
        // doesn't have a tx-size cap (it's an account, ~10KB), so there's no
        // reason for proposers to push accounts into ALT references.
        require_msg!(
            message.address_table_lookups.is_empty(),
            ErrorCode::InvalidMessage,
            "InvalidMessage: address_table_lookups must be empty (use static account_keys instead)"
        );

        // Validate that all instruction indexes are within the static account list.
        let combined_count = message.account_keys.len();
        // Solana's runtime caps total accounts per tx at 256 (u8 index space).
        require_msg!(
            combined_count <= MAX_COMBINED_ACCOUNTS,
            ErrorCode::InvalidMessage,
            "InvalidMessage: account count > 256 (Solana u8 index cap)"
        );
        for ix in &message.instructions {
            // Program cannot be the vault PDA (index 0) — it's not a program.
            // Defensive; runtime would reject otherwise.
            require_msg!(
                ix.program_id_index >= 1,
                ErrorCode::InvalidMessage,
                "InvalidMessage: program_id_index points to vault (index 0)"
            );
            require_msg!(
                (ix.program_id_index as usize) < combined_count,
                ErrorCode::InvalidMessage,
                "InvalidMessage: program_id_index out of bounds"
            );
            for idx in &ix.account_indexes {
                require_msg!(
                    (*idx as usize) < combined_count,
                    ErrorCode::InvalidMessage,
                    "InvalidMessage: account index out of bounds"
                );
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
        // Build the resolved account list. Proposals only carry static
        // account_keys (ALT references inside proposals are rejected at
        // create time — see address_table_lookups.is_empty() check).
        // ============================================================
        let message = &transaction.message;
        let static_count = message.account_keys.len();

        // Defensive: enforce Solana's u8 index cap.
        require!(
            static_count <= MAX_COMBINED_ACCOUNTS,
            ErrorCode::InvalidMessage
        );

        // remaining_accounts must include all the static accounts at the same
        // positions. The executor's V0 outer tx may source these from its own
        // ALT (for tx-size compactness); the equality check below catches any
        // substitution regardless of where each address came from.
        let remaining = ctx.remaining_accounts;
        require!(
            remaining.len() >= static_count,
            ErrorCode::InsufficientRemainingAccounts
        );

        // Static section: every account_keys[i] must match remaining[i].
        // This is the load-bearing security check — it binds every CPI
        // destination to the pubkey the proposer signed off on.
        let mut combined_pubkeys: Vec<Pubkey> = Vec::with_capacity(static_count);
        for (i, expected_key) in message.account_keys.iter().enumerate() {
            require_keys_eq!(
                remaining[i].key(),
                *expected_key,
                ErrorCode::AccountMismatch
            );
            combined_pubkeys.push(*expected_key);
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
            require_msg!(
                program_id_index < static_count,
                ErrorCode::InvalidMessage,
                "InvalidMessage: program_id_index out of bounds at execute"
            );
            let program_id = combined_pubkeys[program_id_index];

            // Build AccountMetas + AccountInfos for the CPI.
            let mut account_metas: Vec<AccountMeta> =
                Vec::with_capacity(compiled.account_indexes.len());
            let mut account_infos: Vec<AccountInfo<'info>> =
                Vec::with_capacity(compiled.account_indexes.len() + 1);

            for &raw_index in &compiled.account_indexes {
                let i = raw_index as usize;
                require!(i < static_count, ErrorCode::InvalidMessage);
                let pubkey = combined_pubkeys[i];

                // is_signer: any of the first num_signers slots are signers.
                let is_signer = i < num_signers;
                // is_writable: writable signers come first, then writable
                // non-signers; everything else is readonly.
                let is_writable = if i < num_writable_signers {
                    true // writable signer
                } else if i < num_signers {
                    false // readonly signer
                } else if i < static_writable_end {
                    true // writable non-signer
                } else {
                    false // readonly non-signer
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

            // Append the program account for the CPI. The program is at
            // `program_id_index` in the static list, positional in
            // remaining_accounts (gated by the bounds checks above).
            let program_info = if program_id == multisig_key {
                multisig_info.clone()
            } else {
                remaining[program_id_index].clone()
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

/// Read the Ed25519 native-program instruction at `ix_index` and confirm it
/// verified one or more signatures over `expected_message`. Returns the list
/// of signer pubkeys harvested from the ix's pubkey entries.
///
/// The native Ed25519 program already performed the cryptographic check
/// before our program ran. Our job is to:
///  - confirm the ix is an Ed25519 program ix,
///  - confirm each entry's `*_instruction_index` is 0xFFFF (i.e. the bytes
///    the Ed25519 program verified are in THIS ix, not some unrelated one),
///  - confirm the message bytes the Ed25519 program verified are exactly
///    the `expected_message` we want signed (defends against signature
///    replay across different multisig configurations),
///  - return the signers so the caller can match them against the member
///    set and threshold.
///
/// The 0xFFFF check is critical: without it, an attacker could craft an
/// Ed25519 ix whose offsets point into a *different* instruction's data
/// (e.g. a previous successful init), causing the Ed25519 program to verify
/// a sig over the OLD message while our byte check pretends it verified
/// our NEW init message.
fn verify_ed25519_batch(
    ix_sysvar: &AccountInfo,
    ix_index: usize,
    expected_message: &[u8],
) -> Result<Vec<Pubkey>> {
    let ix = load_instruction_at_checked(ix_index, ix_sysvar)
        .map_err(|_| ErrorCode::InvalidSignature)?;
    require!(
        ix.program_id == ed25519_program::ID,
        ErrorCode::InvalidSignature
    );

    // Layout (little-endian where multi-byte):
    //   [0]    num_signatures (u8)
    //   [1]    padding (u8)
    //   For each sig (14 bytes starting at offset 2 + i*14):
    //     [+0]  signature_offset (u16)
    //     [+2]  signature_instruction_index (u16, 0xFFFF == current ix)
    //     [+4]  public_key_offset (u16)
    //     [+6]  public_key_instruction_index (u16)
    //     [+8]  message_data_offset (u16)
    //     [+10] message_data_size (u16)
    //     [+12] message_instruction_index (u16)
    //   Then the raw bytes: signatures (64 each) + pubkeys (32 each) + messages.
    let data = &ix.data;
    require!(data.len() >= 2, ErrorCode::InvalidSignature);

    let num = data[0] as usize;
    require!(num >= 1, ErrorCode::InvalidSignature);

    let header_size = 2 + 14 * num;
    require!(data.len() >= header_size, ErrorCode::InvalidSignature);

    let mut signers: Vec<Pubkey> = Vec::with_capacity(num);

    for i in 0..num {
        let entry = 2 + i * 14;

        let sig_offset = u16::from_le_bytes([data[entry], data[entry + 1]]) as usize;
        let sig_ix_index = u16::from_le_bytes([data[entry + 2], data[entry + 3]]);
        let pk_offset = u16::from_le_bytes([data[entry + 4], data[entry + 5]]) as usize;
        let pk_ix_index = u16::from_le_bytes([data[entry + 6], data[entry + 7]]);
        let msg_offset = u16::from_le_bytes([data[entry + 8], data[entry + 9]]) as usize;
        let msg_size = u16::from_le_bytes([data[entry + 10], data[entry + 11]]) as usize;
        let msg_ix_index = u16::from_le_bytes([data[entry + 12], data[entry + 13]]);

        require!(
            sig_ix_index == u16::MAX && pk_ix_index == u16::MAX && msg_ix_index == u16::MAX,
            ErrorCode::InvalidSignature
        );

        // Bounds for sig + pk + message inside the ix data.
        require!(data.len() >= sig_offset + 64, ErrorCode::InvalidSignature);
        require!(data.len() >= pk_offset + 32, ErrorCode::InvalidSignature);
        require!(
            data.len() >= msg_offset + msg_size,
            ErrorCode::InvalidSignature
        );

        // The bytes the Ed25519 program verified MUST be our expected message.
        require!(
            msg_size == expected_message.len(),
            ErrorCode::InvalidSignature
        );
        require!(
            &data[msg_offset..msg_offset + msg_size] == expected_message,
            ErrorCode::InvalidSignature
        );

        // Harvest signer; freshness/dedup against member set is the caller's job.
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&data[pk_offset..pk_offset + 32]);
        signers.push(Pubkey::new_from_array(pk_bytes));
    }

    Ok(signers)
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
#[instruction(member_hash: [u8; 32], threshold: u8)]
pub struct InitializeMultisig<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Multisig::INIT_SPACE,
        seeds = [
            b"multisig",
            member_hash.as_ref(),
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
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(vault_index: u8, message: TransactionMessage)]
pub struct CreateTransaction<'info> {
    #[account(mut)]
    pub multisig: Account<'info, Multisig>,

    /// Sized to the *actual* bytes this specific proposal needs, not the
    /// MAX_* upper bounds. Avoids the 10240-byte System-Program CPI realloc
    /// cap that `init` hits when allocating worst-case-sized accounts.
    /// Proposals whose computed size exceeds `MAX_PROPOSAL_ACCOUNT_BYTES`
    /// will fail at `init` with the runtime's realloc error.
    #[account(
        init,
        payer = creator,
        space = compute_proposal_space(&message),
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

/// Derive multisig PDA from members and threshold.
///
/// CRITICAL: NO PRIVATE KEY GENERATION — only PDA derivation. The full
/// 32-byte sha256 of the sorted member list is used as a seed (not a
/// truncation): truncating to 8 bytes would give attackers a 2^64 preimage
/// to find a colliding member set, which combined with the fact that vault
/// PDAs are derived from the multisig PDA address (not its contents) would
/// let them steal pre-funded vault balances by initializing the multisig
/// at the colliding address with their own keys.
pub fn derive_multisig_pda(members: &[Pubkey], threshold: u8) -> Result<(Pubkey, u8)> {
    let sorted_members = sort_members(members);
    let member_hash = hash_members(&sorted_members);

    let (pda, bump) =
        Pubkey::find_program_address(&[b"multisig", &member_hash, &[threshold]], &crate::ID);

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

/// Compute the exact bytes a `VaultTransaction` account needs to hold a
/// proposal carrying `message`. Anchor's `init` constraint reads this to
/// allocate just-enough space, sidestepping the 10240-byte CPI realloc cap
/// that `8 + VaultTransaction::INIT_SPACE` would hit (since INIT_SPACE
/// expands to the worst case across all `#[max_len]` upper bounds).
///
/// `approvals` is allocated at full `MAX_MEMBERS` capacity because it grows
/// over the proposal's lifetime. Everything inside `message` is allocated
/// to the actual length present at create time — proposals are immutable
/// after creation, so the message vectors never grow.
fn compute_proposal_space(message: &TransactionMessage) -> usize {
    8                                       // anchor discriminator
    + 32                                    // multisig
    + 8                                     // transaction_index
    + 32                                    // creator
    + 1                                     // bump
    + 1                                     // vault_index
    + 1                                     // vault_bump
    + 1                                     // executed
    + 4 + MAX_MEMBERS * 32                  // approvals (Vec<Pubkey>, full cap)
    + 1 + 1 + 1                             // num_signers / num_writable_*
    + 4 + message.account_keys.len() * 32   // account_keys
    + 4 + message
        .instructions
        .iter()
        .map(|ix| 1 + 4 + ix.account_indexes.len() + 4 + ix.data.len())
        .sum::<usize>()                     // instructions (actual)
    + 4 + message
        .address_table_lookups
        .iter()
        .map(|l| 32 + 4 + l.writable_indexes.len() + 4 + l.readonly_indexes.len())
        .sum::<usize>() // address_table_lookups (actual)
}

/// Create the fixed-size init message that members sign off-chain.
///
/// Layout (53 bytes total, regardless of member count):
///   [0..20]  domain separator b"SOLANA_MULTISIG_INIT"
///   [20..52] sha256(sorted_members concatenated raw bytes) — pins the
///            signature to a specific member set
///   [52]     threshold
///
/// Hashing the member list (rather than including each pubkey verbatim) is
/// what lets the Ed25519 verify ix stay small enough that big multisigs fit
/// inside Solana's 1232-byte transaction cap.
fn create_initialization_message(members: &[Pubkey], threshold: u8) -> Vec<u8> {
    let mut message = Vec::with_capacity(20 + 32 + 1);
    message.extend_from_slice(b"SOLANA_MULTISIG_INIT");
    message.extend_from_slice(&hash_members(members));
    message.push(threshold);
    message
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of members in a multisig
pub const MAX_MEMBERS: usize = 20;

/// Maximum number of static account keys per transaction message.
/// All accounts a proposal references must live here (proposals don't
/// support ALT references — see address_table_lookups.is_empty() check
/// in `create_transaction`). 128 is enough headroom for typical Jupiter
/// routes (~30-50 accounts) and most multi-hop DeFi compositions.
///
/// The real ceiling on proposal size is the 10240-byte System Program
/// CPI realloc cap, enforced via dynamic sizing in `compute_proposal_space`.
/// Pathological combinations (128 keys × 16 max-data ixs) won't fit and
/// will fail cleanly at init time with a runtime error.
pub const MAX_TX_ACCOUNT_KEYS: usize = 128;

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
/// Tuned alongside MAX_TX_ACCOUNT_KEYS and MAX_ADDRESS_TABLE_LOOKUPS so that
/// the maximum combined account count never exceeds Solana's 256-account
/// per-tx cap (u8 index space):
///   max_combined = MAX_TX_ACCOUNT_KEYS
///                + MAX_ADDRESS_TABLE_LOOKUPS * 2 * MAX_INDEXES_PER_LOOKUP
///                = 32 + 4 * 2 * 28 = 256
pub const MAX_INDEXES_PER_LOOKUP: usize = 28;

/// Solana hard cap on accounts per transaction (u8 index space).
pub const MAX_COMBINED_ACCOUNTS: usize = 256;

/// Solana caps account allocation done via a CPI to the System Program at
/// 10240 bytes (`MAX_PERMITTED_DATA_LENGTH` for inner ixs). Anchor's `init`
/// constraint goes through that CPI, so a single proposal can't allocate more
/// than this. The constants above represent absolute upper bounds — actual
/// proposals are sized dynamically to the exact bytes they need (most
/// proposals are well under 1KB), and we reject at create time anything that
/// would not fit.
pub const MAX_PROPOSAL_ACCOUNT_BYTES: usize = 10240;

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
