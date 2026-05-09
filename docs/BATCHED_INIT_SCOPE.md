# Batched Multi-Tx Init — Scope Plan

> **Status:** Prepared, not implemented. Ship if/when a customer needs `M ≥ 8`
> threshold initialization.
>
> **Effort estimate:** ~4 days end-to-end across program, SDK, wallet, and tests.
>
> **Reversibility:** Fully additive — existing single-tx init path remains the
> default for `M ≤ 7`. Batched init is a new code path triggered only when
> `M > 7`.

---

## Why this exists

Today's `initialize_multisig` requires every threshold signature to fit in
one tx alongside the program ix. With ALT compression for member account
references, the practical ceiling is **~7 init signatures** (~770 bytes of
ed25519 payload) before the 1232-byte tx cap is exhausted. See
[`README.md` § Init-time threshold ceiling](../README.md#init-time-threshold-ceiling).

Most real-world multisig configurations stay below this:

| Config | Used for | Fits today? |
|---|---|---|
| 2-of-3 | Small team treasury | ✅ |
| 3-of-5 | Mid-size treasury | ✅ |
| 4-of-7 | Standard board | ✅ |
| 5-of-9 | Larger board | ✅ |
| 7-of-10 | Top of one-tx range | ✅ |
| 7-of-30 | Max N at single-tx ceiling | ✅ (after MAX_MEMBERS bump to 30) |
| 8-of-15 | Foundation governance | ❌ |
| 10-of-30 | Large DAO council | ❌ |
| 15-of-15 | Unanimous council | ❌ |

If a customer asks for an `M ≥ 8` configuration (or wants high-N unanimous,
e.g. 15-of-15), this scope is what we'd implement.

## Why not the alternatives

| Alternative | Rejected because |
|---|---|
| **Squads-style creator key** | Loses the no-front-running, no-creator-trust differentiator. The whole reason this program exists. |
| **Schnorr / MuSig signature aggregation** | Solana's native ed25519 verifier doesn't support aggregated sigs. Would require a custom on-chain verifier (lots of compute units, harder audit) or pre-aggregation tooling that adds complexity to wallets/keys. Defer. |
| **Bigger MAX_MEMBERS without protocol change** | Storage isn't the constraint; the init-tx wire budget is. Bumping MAX_MEMBERS without batching just changes the failure mode from "rejected by program" to "rejected by Solana network." |

Multi-tx batched init is the lowest-complexity, highest-leverage path.

## Design

### Security invariants preserved

The whole point of this program is "every member proves consent before they
can be added to a multisig." Batched init must keep that invariant intact.
After the redesign:

- **Each batch is independently authenticated** via its own ed25519_verify
  ix. The program reads sigs from the same instructions sysvar at the same
  index it does today, just across multiple txs.
- **Member set is locked at `init_begin` time** via the same `member_hash`
  binding we use today (`actual_hash == member_hash`). Subsequent batches
  can't add members — they can only collect signatures from the pre-declared
  set.
- **No creator key is introduced.** Anyone can call any of the new ixs;
  the rent payer doesn't gain any privilege.
- **Idempotency on signers.** Re-submitting the same signer in a later
  batch is a no-op (de-dup by `signers_collected`).
- **Final PDA is identical to today's.** `Multisig` PDA derivation is
  unchanged: `find_program_address([b"multisig", member_hash[..8], &[threshold]])`.

### New on-chain state: `InitState`

Temporary PDA holding accumulated init progress. Created by `init_begin`,
closed by `init_finalize` (or via `cleanup_stale_init` after TTL).

```rust
#[account]
#[derive(InitSpace)]
pub struct InitState {
    pub member_hash: [u8; 32],
    pub threshold: u8,
    #[max_len(MAX_MEMBERS)]
    pub members: Vec<Pubkey>,           // sorted, copied at init_begin
    #[max_len(MAX_MEMBERS)]
    pub signers_collected: Vec<Pubkey>, // grows as batches verify
    pub created_at: i64,                // unix seconds, for stale cleanup
    pub bump: u8,
}
```

PDA seeds: `[b"init_state", &member_hash, &[threshold]]`.

Rent cost: ~0.005 SOL temporary, refunded at `init_finalize`.

### New instructions

#### 1. `init_begin(member_hash, threshold, members)`

Creates the `InitState` PDA. Validates:
- `members.len() <= MAX_MEMBERS`
- `threshold > 0 && threshold <= members.len()`
- `members` is sorted ascending, no duplicates
- `hash_members(&sorted) == member_hash`

Stores `members` and metadata. `signers_collected` starts empty.

Anyone can call this — there's no privilege. The PDA address is determined
by `(member_hash, threshold)` so concurrent racers converge on the same
state account.

#### 2. `init_register_batch()`

Reads ed25519_verify ix at index 0 of the current tx. Each verified
signature must be over the canonical init message
`SOLANA_MULTISIG_INIT || sha256(sorted_members) || threshold` — same format
as today's single-tx init. The program:

- Loads `InitState` (must exist, must not be finalized)
- Re-derives `init_message` from `InitState.members` + `threshold`
- Calls existing `verify_ed25519_batch(instructions_sysvar, 0, &init_message)`
  to harvest verified signers
- For each verified signer: rejects if not in `InitState.members`; appends
  to `signers_collected` if not already present (idempotent)

Each batch carries up to ~4 sigs comfortably (saving headroom for tx fee
slop, blockhash freshness, retry support).

Anyone can pay for this ix. The relay paymaster broadcasts batches on
behalf of members.

#### 3. `init_finalize()`

Once `signers_collected.len() >= threshold`:
- Creates the actual `Multisig` PDA via Anchor's `init` constraint, seeds
  identical to today
- Copies `InitState.members` and `threshold` into the new account
- Sets `transaction_index = 0`, stores `bump`
- Closes `InitState`, refunding rent to the original `init_begin` payer

Fails if `signers_collected.len() < threshold` (returns
`InsufficientSignatures` — same error as today).

#### 4. `cleanup_stale_init()` (optional, defer if rushed)

Anyone can close an `InitState` PDA whose `created_at` is older than e.g.
24 hours. Refunds rent to caller as a small bounty for cleanup. Prevents
rent-locked PDAs accumulating from abandoned init attempts.

### Client flow

```
member_hash = sha256(sorted_members)
threshold = M

# Step 1: anyone calls init_begin (could be the relay)
tx_begin = init_begin(member_hash, threshold, sorted_members)
broadcast(tx_begin)

# Step 2: collect M signatures over init_message off-chain
init_message = SOLANA_MULTISIG_INIT || member_hash || threshold
sigs = [member_i.sign(init_message) for i in approving_members]

# Step 3: split sigs into batches of ~4
batches = chunks(sigs, batch_size=4)
for batch in batches:
    ed25519_ix = makeBatchedEd25519Ix(batch, init_message)
    register_ix = init_register_batch()
    tx = Transaction([ed25519_ix, register_ix], payer=relay_paymaster)
    broadcast(tx)

# Step 4: finalize once batches collectively cover threshold
tx_finalize = init_finalize()
broadcast(tx_finalize)
```

Tx counts by configuration:

| Config | Sigs | Batches (4 per tx) | Total txs |
|---|---|---|---|
| 7-of-10 | 7 | 2 | 4 (begin + 2 batches + finalize) |
| 8-of-15 | 8 | 2 | 4 |
| 10-of-15 | 10 | 3 | 5 |
| 15-of-20 | 15 | 4 | 6 |
| 20-of-20 | 20 | 5 | 7 |

### Backward compatibility

Existing `initialize_multisig` (single-tx) stays in place unchanged. Clients
choose which path based on `M`:

```ts
if (threshold <= 7) {
  // Use existing initialize_multisig — single tx, faster
  return submitInitTxViaAlt({ ... });
} else {
  // Use new batched flow — multiple txs
  return submitBatchedInit({ ... });
}
```

No on-chain state migration. Existing multisigs unaffected.

## Edge cases & open questions

1. **Concurrent batches racing.** Two payers submitting `init_register_batch`
   with overlapping signers in the same slot — second tx's idempotency dedup
   handles it gracefully (no error, no double-count).
2. **Blockhash expiry between batches.** Each batch has its own recent
   blockhash; if one expires, retry that batch only — earlier batches'
   contributions remain in `InitState`.
3. **Rent payer refund routing.** `init_begin` payer should be recorded on
   `InitState` so `init_finalize` refunds the right account (not whoever
   happens to call finalize).
4. **TTL for stale state.** 24h default; configurable. Long enough for
   ceremony-coordinated multisig setups, short enough to avoid PDA squat.
5. **Member set lock-in moment.** Currently fixed at `init_begin`. Members
   must be sorted+committed up front. Trying to add/remove a member
   mid-collection means starting over with a new `InitState` (different
   PDA derived from new `member_hash`).
6. **Should batches be ordered?** No — order-independent collection
   simplifies the relay's life and is safe (we still need ≥ threshold
   unique signers regardless of insertion order).

## Implementation checklist

### Program (`programs/solana-multisig/src/lib.rs`)

- [ ] Add `InitState` account struct with `#[account]` and `#[derive(InitSpace)]`
- [ ] Add `init_begin` instruction with `Initialize` context (account = InitState)
- [ ] Add `init_register_batch` instruction
- [ ] Add `init_finalize` instruction with `Initialize` context (account = Multisig)
- [ ] Add `cleanup_stale_init` instruction (optional v1.1)
- [ ] New error codes: `InitStateAlreadyExists`, `InitStateNotFound`,
      `InitStateAlreadyFinalized`, `MemberNotInDeclaredSet`, `InitStateNotStale`
- [ ] PDA seed constant `INIT_STATE_SEED = b"init_state"`

### Tests (`tests/`)

- [ ] `phase7-batched-init.ts`:
  - [ ] Happy path: 8-of-15, 10-of-15, 15-of-20, 20-of-20
  - [ ] Idempotent re-registration of same signer
  - [ ] Reject batch with signer not in declared member set
  - [ ] Reject finalize with insufficient signers
  - [ ] Reject finalize when InitState doesn't exist
  - [ ] Verify final Multisig PDA matches single-tx-init PDA for same `(members, threshold)`
  - [ ] Stale cleanup after TTL
  - [ ] Race: two concurrent `init_register_batch` with overlapping signers

### SDK (`sdk/src/`)

- [ ] `BatchedInitClient` exposing:
  - [ ] `prepareBatchedInit({ members, threshold, batchSize? })` returning ordered tx sequence
  - [ ] `buildInitBeginTx()`, `buildBatchTx(sigs)`, `buildFinalizeTx()` — composable primitives
  - [ ] Helper to chunk signatures into batches
- [ ] Auto-route in existing `setupMultisigViaAlt`:
  `if threshold > 7 → batched`, `else → single-tx`
- [ ] Update IDL + types

### Wallet/Key/Relay integration (post-program-deploy)

- [ ] ssp-wallet: detect `M > 7` at vault create time, switch to batched UI
      (members sign their batches sequentially, paymaster broadcasts)
- [ ] ssp-key: support multi-batch signing flow
- [ ] ssp-relay/enterprise: orchestrate batch broadcast, handle retries
- [ ] Cap UI at `MAX_MEMBERS = 20` (program ceiling, unchanged)

## Risk assessment

| Risk | Mitigation |
|---|---|
| Bug in `init_register_batch` accepting non-canonical sig | Tests re-derive init_message from on-chain InitState.members; reject if mismatched |
| Stale `InitState` PDAs accumulating | `cleanup_stale_init` ix + 24h TTL |
| Member set spoofing via `init_begin` | `member_hash` binding (same as today's `initialize_multisig`) |
| Replay across devnet/mainnet | Init message includes no chain id; relies on PDA being chain-specific (which it is — different programs IDs derive different PDAs) |
| Multi-tx UX worse than single-tx | Acceptable trade — batched flow only used for `M > 7` which is rare |

## When to ship this

**Don't ship preemptively.** Reasons:
- Single-tx init covers the vast majority of multisigs (everything ≤ 7-of-N)
- Batched init adds ~250-300 lines of program code, ~150 lines of SDK,
  ~100 lines of wallet/key/relay glue — all of which becomes audit surface
- Customer-driven prioritization is better than speculative work

**Ship trigger:** A customer or design partner explicitly requests an
`M ≥ 8` configuration that they can't work around (e.g., regulatory
requirement for 8-of-15 board approval).

When that happens: this scope is ready to execute. Estimated 4 days
with the existing program/SDK author productive.

## See also

- [`README.md` § Init-time threshold ceiling](../README.md#init-time-threshold-ceiling)
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — current single-tx init flow
- `programs/solana-multisig/src/lib.rs:60-157` — current `initialize_multisig`
  implementation
- `tests/phase4-integration.ts:283` — largest tested config today (7-of-10)
