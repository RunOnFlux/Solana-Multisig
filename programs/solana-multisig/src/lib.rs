use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::system_program::{
    create_nonce_account_with_seed, CreateNonceAccountWithSeed,
};

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

    /// Initialize a multisig at its deterministic PDA. Permissionless.
    ///
    /// The multisig PDA is `find_program_address(["multisig", member_hash,
    /// threshold], program_id)` where `member_hash = sha256(sorted_members)`.
    /// Anyone can call this — there is nothing to steal by front-running
    /// because (a) the PDA address is fully determined by the inputs, so
    /// initializing with different inputs lands at a different address and
    /// cannot squat the canonical vault address, and (b) no funds exist at
    /// the PDA prior to init. Authorization is enforced by the M-of-N
    /// threshold on `create_transaction` / `approve_transaction` /
    /// `execute_transaction`, not on registration.
    ///
    /// This mirrors how P2WSH multisig works on Bitcoin: the address IS
    /// the hash of the script (members + threshold). No init signatures
    /// are required because there is no way to subvert the canonical
    /// address without the canonical inputs.
    ///
    /// Members are passed via `remaining_accounts` (typically resolved
    /// from an Address Lookup Table so each costs ~1 byte instead of 32).
    /// `member_count` is an ix arg so Anchor can size the account exactly.
    pub fn initialize_multisig<'info>(
        ctx: Context<'_, '_, '_, 'info, InitializeMultisig<'info>>,
        member_hash: [u8; 32],
        threshold: u8,
        member_count: u8,
    ) -> Result<()> {
        // Harvest members from remaining_accounts. The client typically
        // sources these from an ALT, but the program doesn't care — they
        // can also be passed as static accounts.
        let members: Vec<Pubkey> = ctx.remaining_accounts.iter().map(|a| a.key()).collect();

        // member_count is an instruction arg so the `init` constraint can
        // size the account exactly (instead of always allocating MAX_MEMBERS
        // bytes). Verify the client-supplied count matches reality — a
        // mismatch would mean the account allocation doesn't fit the data.
        require!(
            members.len() == member_count as usize,
            ErrorCode::InvalidMemberCount
        );

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

        // Initialize the multisig account.
        let bump = ctx.bumps.multisig;
        let multisig = &mut ctx.accounts.multisig;
        multisig.members = sorted_members;
        multisig.threshold = threshold;
        multisig.transaction_index = 0;
        multisig.bump = bump;

        msg!(
            "✅ Multisig initialized: {} members, threshold {}",
            members.len(),
            threshold,
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
        transaction.payer = ctx.accounts.payer.key();
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

    /// Close an executed proposal account, refunding rent to the account that
    /// originally funded it (`transaction.payer`).
    ///
    /// Garbage collection: the proposal has done its job (coordinated
    /// approvals, gated execution) and is read-only history afterwards. Closing
    /// recovers the ~0.007 SOL rent. Wallets typically bundle this into the
    /// same outer tx as `execute_transaction` so close is atomic with execute.
    ///
    /// Constraints (most enforced via Anchor account constraints):
    ///   - proposal must be executed (executed = true)
    ///   - signer must equal stored `transaction.payer` (has_one)
    ///   - rent refunds to payer (close = payer)
    pub fn close_transaction(ctx: Context<CloseTransaction>, transaction_index: u64) -> Result<()> {
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
        require!(transaction.executed, ErrorCode::NotExecuted);

        msg!(
            "✅ Transaction {} closed; rent refunded to payer {}",
            transaction_index,
            ctx.accounts.payer.key()
        );

        Ok(())
    }

    /// Provision a durable nonce account at a deterministic address derived
    /// from this multisig. Permissionless — anyone can pay the rent to
    /// provision; the `payer` becomes the nonce's initial authority and is
    /// typically the relay paymaster.
    ///
    /// The nonce account address is
    ///   `Pubkey::create_with_seed(multisig_pda, NONCE_SEED, system_program::ID)`
    /// so any client can re-derive it from the multisig alone — no DB,
    /// no on-chain bookkeeping, paymaster-rotation safe (rotation just
    /// transfers authority via `SystemProgram::nonceAuthorize`; address
    /// stays the same).
    ///
    /// Once provisioned, this nonce is used by clients (wallet/key) as the
    /// `recent_blockhash` in send transactions, with `SystemProgram::
    /// nonceAdvance` as ix[0]. That eliminates the 60-second blockhash
    /// expiry race that would otherwise plague flows where wallet pre-signs
    /// and Key signs later (after user approval).
    ///
    /// Idempotent in spirit: callable once per multisig (SystemProgram's
    /// `createAccountWithSeed` will fail if the account already exists,
    /// which clients should treat as success — the nonce is already
    /// available).
    pub fn provision_nonce(ctx: Context<ProvisionNonce>) -> Result<()> {
        // Derive the multisig PDA's signer seeds so SystemProgram's
        // create_account_with_seed will accept invoke_signed for "base".
        // We need member_hash (sha256 of sorted_members, which is what
        // the multisig PDA was originally derived from).
        let member_hash = hash_members(&ctx.accounts.multisig.members);
        let threshold_byte = [ctx.accounts.multisig.threshold];
        let bump_byte = [ctx.accounts.multisig.bump];
        let multisig_signer_seeds: &[&[&[u8]]] = &[&[
            b"multisig",
            &member_hash,
            &threshold_byte,
            &bump_byte,
        ]];

        let rent_lamports = ctx.accounts.rent.minimum_balance(NONCE_ACCOUNT_LENGTH);
        let authority = ctx.accounts.payer.key();

        // Single Anchor helper that emits two CPIs in sequence:
        //   1. SystemProgram::create_account_with_seed (multisig PDA as base,
        //      payer funds rent, address verified deterministic)
        //   2. SystemProgram::nonce_initialize (payer as authority)
        // invoke_signed uses the multisig's seeds so the System Program
        // accepts the multisig PDA as the seed-derivation base.
        create_nonce_account_with_seed(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                CreateNonceAccountWithSeed {
                    from: ctx.accounts.payer.to_account_info(),
                    nonce: ctx.accounts.nonce_account.to_account_info(),
                    base: ctx.accounts.multisig.to_account_info(),
                    recent_blockhashes: ctx
                        .accounts
                        .recent_blockhashes
                        .to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
            )
            .with_signer(multisig_signer_seeds),
            rent_lamports,
            NONCE_SEED,
            &authority,
        )?;

        msg!(
            "✅ Nonce account provisioned at {} (authority: {})",
            ctx.accounts.nonce_account.key(),
            authority
        );

        Ok(())
    }
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

    /// Member who created the proposal (authorizer; NOT the rent funder).
    pub creator: Pubkey,

    /// Account that funded the proposal's rent at create time. `close_transaction`
    /// refunds rent here. Decoupled from `creator` so a paymaster can pay rent
    /// while a leaf member authorizes.
    pub payer: Pubkey,

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
#[instruction(member_hash: [u8; 32], threshold: u8, member_count: u8)]
pub struct InitializeMultisig<'info> {
    /// Sized to the *actual* member count (4 + N×32 bytes for the members
    /// vec, vs. 4 + 30×32 if we always allocated MAX_MEMBERS). The handler
    /// verifies `member_count == remaining_accounts.len()` to prevent the
    /// allocation from being smaller than the data we then write.
    #[account(
        init,
        payer = payer,
        space = compute_multisig_space(member_count as usize),
        seeds = [
            b"multisig",
            member_hash.as_ref(),
            &[threshold],
        ],
        bump
    )]
    pub multisig: Account<'info, Multisig>,

    /// Anyone can pay — init is permissionless. The fee payer of the outer
    /// tx pays the rent; no signature from any member is required.
    #[account(mut)]
    pub payer: Signer<'info>,

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
    #[account(
        init,
        payer = payer,
        space = compute_proposal_space(&message),
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &(multisig.transaction_index + 1).to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, VaultTransaction>,

    /// Multisig member authorizing the proposal. Verified against the member
    /// set inside the handler. Does NOT pay rent — that's `payer`.
    pub creator: Signer<'info>,

    /// Funds the proposal account's rent. Decoupled from `creator` so the
    /// SSP relay paymaster can underwrite proposal storage without each
    /// member's leaf needing a SOL balance. Stored on the proposal so
    /// `close_transaction` refunds rent back to this same account.
    #[account(mut)]
    pub payer: Signer<'info>,

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

#[derive(Accounts)]
#[instruction(transaction_index: u64)]
pub struct CloseTransaction<'info> {
    /// Read-only reference — used only to derive the transaction PDA seeds.
    pub multisig: Account<'info, Multisig>,

    /// The proposal account being closed. Anchor's `close = payer` sweeps the
    /// rent deposit into the payer account and zeros the data + discriminator,
    /// returning it to system-owned state. `has_one = payer` enforces that
    /// the signer matches the account that originally funded the rent.
    #[account(
        mut,
        close = payer,
        has_one = payer @ ErrorCode::UnauthorizedCloser,
        seeds = [
            b"transaction",
            multisig.key().as_ref(),
            &transaction_index.to_le_bytes(),
        ],
        bump
    )]
    pub transaction: Account<'info, VaultTransaction>,

    /// Receives the rent refund. Must match the proposal's stored `payer`.
    /// Signer requirement prevents a third party from closing someone else's
    /// proposal to grief them.
    #[account(mut)]
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProvisionNonce<'info> {
    /// The multisig — used as the seed base for the nonce account address
    /// (so the address is paymaster-independent and any client can re-derive
    /// it from the multisig alone).
    pub multisig: Account<'info, Multisig>,

    /// The durable nonce account being created. Its address must equal
    /// `Pubkey::create_with_seed(multisig.key(), NONCE_SEED, system_program::ID)`
    /// — SystemProgram's `createAccountWithSeed` CPI rejects any other address.
    /// Owned by SystemProgram once initialized.
    /// CHECK: address-validated by SystemProgram inside the CPI.
    #[account(mut)]
    pub nonce_account: UncheckedAccount<'info>,

    /// Funds the nonce account's rent and becomes the initial authority.
    /// Permissionless — anyone can call this; typically the SSP relay
    /// paymaster does it.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Required by SystemProgram::nonceInitialize. Must be the recent
    /// blockhashes sysvar account.
    /// CHECK: address checked against the canonical sysvar ID.
    #[account(address = anchor_lang::solana_program::sysvar::recent_blockhashes::ID)]
    pub recent_blockhashes: UncheckedAccount<'info>,

    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
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

/// Compute the exact bytes a `Multisig` account needs to hold N members.
/// Anchor's `init` constraint reads this so the allocation matches reality
/// instead of always reserving `MAX_MEMBERS=30` slots. A 2-of-2 consumer
/// multisig drops from 982 bytes to 86 bytes — multisig PDA rent falls
/// from ~0.0077 SOL to ~0.003 SOL.
///
/// The Multisig struct never grows after init (members + threshold are
/// immutable; transaction_index increments in place; bump is fixed), so
/// sizing exactly is safe.
fn compute_multisig_space(member_count: usize) -> usize {
    8                          // anchor discriminator
    + 4 + member_count * 32    // members (Vec<Pubkey>, exact length)
    + 1                        // threshold
    + 8                        // transaction_index
    + 1                        // bump
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
    + 32                                    // payer
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

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of members in a multisig.
///
/// Bumped from 20 → 30 to support enterprise dual-signing-mode vaults
/// where each SSP signer enrolls 2 ed25519 keys (wallet leaf + key leaf).
/// At 30 members the program can hold 15 SSP signers in dual mode
/// (15 × 2 = 30) while preserving the no-creator-key init flow.
///
/// Init is permissionless (no per-member ed25519 ix to fit in the tx),
/// so there is no signer-count ceiling on init — the cap is just the
/// account space (MAX_MEMBERS × 32 bytes ≈ within rent limits).
pub const MAX_MEMBERS: usize = 30;

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

/// Seed used with `Pubkey::create_with_seed(multisig.key(), NONCE_SEED, system_program::ID)`
/// to deterministically derive the durable nonce account address for a multisig.
///
/// Must be a `&str` (not `&[u8]`) because that's the exact type
/// `SystemProgram::create_account_with_seed` expects.
pub const NONCE_SEED: &str = "nonce";

/// Size of a Solana durable nonce account (matches the System Program's
/// `nonce::State::size()`). 4 (version) + 4 (state tag) + 32 (authority)
/// + 32 (nonce) + 8 (fee_calculator).
pub const NONCE_ACCOUNT_LENGTH: usize = 80;

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid threshold: must be > 0 and <= number of members")]
    InvalidThreshold,

    #[msg("Too many members: maximum is 30")]
    TooManyMembers,

    #[msg("Duplicate members not allowed")]
    DuplicateMembers,

    #[msg("Invalid PDA derivation")]
    InvalidPDA,

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

    #[msg("Cannot close transaction: not yet executed")]
    NotExecuted,

    #[msg("Only the original payer can close an executed transaction")]
    UnauthorizedCloser,

    #[msg("Member count argument does not match the provided members list")]
    InvalidMemberCount,
}
