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

Seed: `[b"multisig", sha256(sorted_members), &[threshold]]` (full 32 bytes — truncation would let an attacker find a colliding member set with ~2^64 work and squat pre-funded vault balances)

Created once via `initialize_multisig`. Members and threshold are immutable after init — to "rotate keys" migrate funds to a new multisig with new keys.

### Nonce PDA — durable nonce (system-owned, 80 bytes)

```
Pubkey::createWithSeed(multisigPda, "nonce", SystemProgram)
```

Provisioned via the `provision_nonce` ix using `invoke_signed` with the multisig PDA as the `createAccountWithSeed` base, so the address is purely a function of the multisig — paymaster-independent, re-derivable from the multisig alone.

The nonce account stores a 32-byte nonce hash that acts as a long-lived `recent_blockhash` for txes containing `SystemProgram.nonceAdvance` at ix[0]. Used by SSP to eliminate the 60s blockhash-expiry race when wallet pre-signs a tx that Key signs/broadcasts minutes later (after user approves on phone).

Authority on the nonce account starts as `payer` (typically the relay paymaster). Transferable via standard `SystemProgram.nonceAuthorize` — address never changes on paymaster rotation.

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
| Front-running init | PDA derived from `(sorted_members, threshold)`; attacker initing with different members lands at a different PDA (no relationship to canonical vault); attacker initing with canonical inputs just pays our rent |
| Squatting the canonical address with wrong members | Program verifies `actual_hash(sorted(remaining_accounts)) == member_hash`; Anchor `init` seeds bind the PDA to `member_hash`. Both constraints together = the canonical address can only ever store the canonical member set |
| Single-creator control | No creator role exists. Init is permissionless. Funds are gated solely by the M-of-N threshold check on `create_transaction` / `approve_transaction` / `execute_transaction` |
| Pre-fund hijacking | Vault is system-owned + empty data; can't be reassigned externally |
| Re-init | Anchor `init` constraint — PDA can only be initialized once |
| Member-set / threshold tampering post-init | No instruction modifies `members`, `threshold`, or `bump` — they're write-once at init |
| Re-entrancy | `executed = true` flushed via `Account::exit()` before CPIs |
| Recursive `create_transaction` from within execute | `multisig` is immutable in `ExecuteTransaction`; outer tx's mut requirement conflicts |
| Counter collision (concurrent proposals) | `transaction_index` incremented atomically at create |
| Account validation | Anchor seeds + bump + owner checks on every account |
| Solana account-cap (256) bypass | Runtime check `combined_count <= 256` at create + execute |

## Init flow detail

Init is **permissionless** — no member signatures required. Tx layout:

```
ix[0] = initialize_multisig(member_hash, threshold, member_count)
  accounts:
    multisig:       PDA at seeds=[b"multisig", member_hash, [threshold]] (init)
    payer:          signer (rent payer — any keypair)
    system_program: 11111111111111111111111111111111
  remaining_accounts: the M member pubkeys (sorted; typically via ALT for compact encoding)
```

The program then:
1. Reads the M member pubkeys from `remaining_accounts`
2. Validates `member_count == remaining_accounts.len()` (so account allocation matches data)
3. Sorts + dedups members
4. Computes `actual_hash = sha256(sorted_members)` and rejects if `actual_hash != member_hash`
5. Stores the canonical config at the PDA

The hash check + Anchor's `init` seeds binding together guarantee that the canonical PDA can only ever be registered with the canonical `(sorted_members, threshold)` tuple. Funds at the resulting vault address (derived from the multisig PDA) move only via the threshold-gated proposal flow.

This mirrors how Bitcoin P2WSH multisig works: the address IS the hash of the script (members + threshold), anyone can fund it, only valid script-satisfying signatures can spend it.

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
