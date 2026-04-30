# Architecture

## Layer overview

```
┌─────────────────────────────────────────┐
│           Client / SSP UI               │
│  Phantom-style wallets, SSP enterprise  │
│  app, custom dApps                       │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│           TypeScript SDK                │
│  - Address derivation                   │
│  - Off-chain signature creation         │
│  - Transaction message builder          │
│  - High-level method wrappers           │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│       Anchor Program (Rust)             │
│  - PDA derivation (multisig + vault)    │
│  - Ed25519 sysvar-based init verify     │
│  - Proposal storage (V0 message)        │
│  - Vault-as-signer CPI execution        │
└─────────────────────────────────────────┘
```

## On-chain accounts

### Multisig PDA — governance / config (program-owned, has data)

```rust
pub struct Multisig {
    pub members: Vec<Pubkey>,    // sorted, deduped
    pub threshold: u8,
    pub transaction_index: u64,  // atomic counter, incremented at create
    pub is_initialized: bool,
    pub bump: u8,
}
```

Seed: `[b"multisig", hash(sorted_members)[..8], &[threshold]]`

Created once via `initialize_multisig`. Members and threshold are immutable after init — to "rotate keys" migrate funds to a new multisig with new keys.

### Vault PDA — funds (system-owned, no data)

Derived once for any `vault_index`:

Seed: `[b"vault", multisig.key, &[vault_index]]`

Never explicitly created — exists as an address. Anyone can transfer SOL or create SPL token accounts (ATAs) at this address before the multisig is even initialized. `SystemProgram::transfer` from the vault works because it's system-owned with empty data.

`vault_index` is a `u8` (0–255). Each multisig supports up to 256 sub-vaults; SSP convention is `vault_index = 0`.

### VaultTransaction PDA — proposal (program-owned, has data)

```rust
pub struct VaultTransaction {
    pub multisig: Pubkey,
    pub transaction_index: u64,
    pub creator: Pubkey,
    pub bump: u8,
    pub vault_index: u8,           // which vault this proposal targets
    pub vault_bump: u8,            // cached for invoke_signed at execute
    pub executed: bool,
    pub approvals: Vec<Pubkey>,    // up to MAX_MEMBERS
    pub message: TransactionMessage,
}
```

Seed: `[b"transaction", multisig.key, &transaction_index.to_le_bytes()]`

Each proposal targets ONE vault (`vault_index`). Cross-vault transactions are not supported in v1; do them as separate proposals.

### TransactionMessage — V0-style stored message

```rust
pub struct TransactionMessage {
    pub num_signers: u8,
    pub num_writable_signers: u8,
    pub num_writable_non_signers: u8,
    pub account_keys: Vec<Pubkey>,           // [0] = vault PDA
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<MessageAddressTableLookup>,
}
```

Mirrors Solana's MessageV0 minus `recent_blockhash` and `fee_payer`. Account references in `instructions` are 1-byte indexes into the combined account list (`account_keys` + ALT-loaded writable + ALT-loaded readonly), not raw 32-byte pubkeys — big storage win for proposals that touch many accounts (Jupiter swaps with ~50 accounts fit comfortably).

## Lifecycle

```
                 ┌──────────────────┐
       (1) DERIVE: multisig + vault addresses (off-chain, free)
                 └──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
       (2) PRE-FUND vault address (anyone, no on-chain init needed)
                 └──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
       (3) INIT: threshold members sign canonical message;
           submit Ed25519 verify ixs + initialize_multisig in one tx
                 └──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
       (4) CREATE proposal: store TransactionMessage on VaultTransaction PDA
                 └──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
       (5) APPROVE: members call approve_transaction one by one
                 └──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
       (6) EXECUTE: program flushes executed=true, then CPIs each
           compiled instruction with VAULT as signer (invoke_signed)
                 └──────────────────┘
```

## Security guarantees

| Threat | Mitigation |
|---|---|
| Front-running init | PDA derived from `(members, threshold)`; attacker with different config gets different PDA |
| Single-creator control | Init requires threshold member sigs of canonical message; no one party controls |
| Pre-fund hijacking | Vault is system-owned + empty data; can't be reassigned externally |
| Signature forgery via instruction_index manipulation | Ed25519 verify ix MUST have `instruction_index = 0xFFFF` (current ix) |
| Replay across multisigs | Init message binds `(members, threshold)` |
| Re-entrancy | `executed = true` flushed via `Account::exit()` before CPIs |
| Recursive `create_transaction` from within execute | `multisig` is immutable in `ExecuteTransaction`; outer tx's mut requirement conflicts |
| Counter collision (concurrent proposals) | `transaction_index` incremented atomically at create |
| Account validation | Anchor seeds + bump + owner checks on every account |
| Solana account-cap (256) bypass | Runtime check `combined_count <= 256` at create + execute |

## Init flow detail

The program verifies signatures on-chain via Solana's native Ed25519 SigVerify program through the Instructions Sysvar:

```
Tx layout:
  ix[0] = Ed25519 verify (member1's signature)
  ix[1] = Ed25519 verify (member2's signature)
  ...
  ix[N] = initialize_multisig(members, threshold, signatures)

For each signature at sig_index = 0..N-1:
  - Load ix at sysvar position `sig_index`
  - Require program_id = ed25519_program::ID
  - Require signature_instruction_index, public_key_instruction_index,
    message_instruction_index ALL = 0xFFFF (current ix only)
  - Validate bytes at offsets match expected (signer, signature, message)
```

The Ed25519 program performs the actual cryptographic verification. Our code validates the instruction is well-formed and bound to our expected (signer, message) tuple — the `0xFFFF` requirement prevents an attacker from binding a valid signature for a different message to our init.

## Execute flow detail

```rust
// 1. Validate (immutable read)
require!(transaction.multisig == multisig.key());
require!(transaction.transaction_index == arg_index);
require!(!transaction.executed);
require!(transaction.approvals.len() >= multisig.threshold);

// 2. Mark executed BEFORE CPIs (re-entrancy guard)
transaction.executed = true;
transaction.exit(ctx.program_id)?;  // flush to on-chain data

// 3. Resolve combined account list
combined = [
    ...message.account_keys,                  // static
    ...remaining[static_count..]              // ALT-loaded
]

// 4. CPI each compiled instruction with vault as signer
let vault_seeds = &[b"vault", multisig.key, &[vault_index], &[vault_bump]];
for compiled in message.instructions {
    let metas = compiled.account_indexes.map(|i| AccountMeta {
        pubkey: combined[i],
        is_signer: i < num_signers,                           // header-derived
        is_writable: /* derived from header sections */,
    });
    invoke_signed(&Instruction { ... }, &account_infos, &[vault_seeds])?;
}
```

## Self-initiating property — preserved across the architecture

Even though we have a vault concept (Squads-style), the self-initiating property holds:

- **Multisig PDA address** is deterministic from `(members, threshold)`
- **Vault PDA address** is deterministic from `(multisig PDA, vault_index)` = deterministic from `(members, threshold, vault_index)`
- Both addresses are computable BEFORE any on-chain action
- Vault can be pre-funded (it's just a system PDA)
- Multisig can be pre-funded too (Anchor handles pre-funded init), but typical SSP flow funds the vault, not the multisig
- Init requires threshold consent — no single-creator dominance

The architecture matches Squads V4 in vault-vs-multisig separation, but the multisig identity model is fundamentally different — Squads requires a `create_key` (random pubkey provided at create), making their multisigs NOT self-initiating.
