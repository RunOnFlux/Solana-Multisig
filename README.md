# SSP Solana Multisig

A self-initiating Solana multisig program where the multisig address is **deterministically derived from members + threshold**. Anyone can derive the address before any on-chain action; anyone can pre-fund the vault; **registration is permissionless** — no member signatures are required at init because the canonical PDA can only ever store the canonical member set (sha256 binding). Fund safety is enforced by the threshold check on `create_transaction` / `approve_transaction` / `execute_transaction`, not on registration. This mirrors how Bitcoin P2WSH multisig works: the address IS the hash of the script.

Devnet Program ID: `CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX`

## Why "self-initiating"

Standard Solana multisigs (Squads V4 etc.) require a creator account to call `multisig_create_v2` with a random `create_key`. The address is unknowable until creation, and the creator is a single point of trust.

Here, the multisig PDA is derived from `(sorted_members, threshold)` directly:

```
multisig_pda = find_program_address(
  [b"multisig", sha256(sorted_members), &[threshold]],  // full 32-byte hash
  program_id
)
```

Implications:
- ✅ Address is knowable BEFORE any on-chain action — pre-fundable
- ✅ No creator role exists at any point — registration is permissionless; only the M-of-N threshold check gates funds
- ✅ Same `(members, threshold)` always yields the same address — no front-run
- ✅ Front-run protection: an attacker initing with different members lands at a different PDA (no harm); initing with canonical inputs just pays our rent

## Architecture

Two PDA types per multisig:

| PDA | Holds | Owner | Purpose |
|---|---|---|---|
| **Multisig** | members, threshold, tx counter | Our program | Governance / config |
| **Vault** | SOL + SPL tokens (via ATAs) | SystemProgram (no data) | Funds storage |

```
multisig_pda = [b"multisig", sha256(sorted_members), &[threshold]]   // full 32 bytes
vault_pda    = [b"vault", multisig_pda, &[vault_index]]              // vault_index 0..255
```

Users send funds TO the vault address. `SystemProgram::transfer` from the vault works because it's system-owned with empty data. Each multisig supports up to 256 vault sub-accounts (most use cases use only `vault_index = 0`).

## Lifecycle

1. **Derive** `(multisig_pda, vault_pda)` off-chain from members + threshold
2. **Pre-fund** the vault address with SOL or SPL (anyone, before init)
3. **Init**: anyone (typically the relay paymaster, or a wallet bundling init into a first send) calls `initialize_multisig(member_hash, threshold, member_count)` with members in `remaining_accounts`. The program verifies `actual_hash(sorted(remaining_accounts)) == member_hash` and stores the canonical config at the PDA. No member signatures involved.
4. **Propose**: a member calls `create_transaction(vault_index, message)` storing a V0-style transaction message (header + account_keys + compiled instructions + ALT lookups) on a `VaultTransaction` PDA.
5. **Approve**: each member calls `approve_transaction(index)` once. Approvals accumulate.
6. **Execute**: when approvals ≥ threshold, anyone calls `execute_transaction(index)`. The program flushes `executed = true` (re-entrancy guard), then iterates compiled instructions and CPIs each one with the **vault PDA as signer** via `invoke_signed`.

## Quick start

```typescript
import { SolanaMultisigClient, deriveVaultAddress } from "@runonflux/solana-multisig";
import { Connection, PublicKey, SystemProgram } from "@solana/web3.js";

const client = new SolanaMultisigClient(connection, programId);

// Derive addresses (free, off-chain)
const multisig = client.deriveAddress(members, threshold);
const [vault] = deriveVaultAddress(multisig, 0, programId);

// Pre-fund vault, then init (permissionless — no member sigs needed):
await client.initialize(members, threshold, payer);

// Propose a SOL transfer
const transferIx = SystemProgram.transfer({
  fromPubkey: vault,
  toPubkey: recipient,
  lamports: 0.1 * 1e9,
});
const proposal = await client.createTransaction(multisig, 0, [transferIx], member);

// Threshold approvals + execute
await client.approveTransaction(multisig, proposal.transactionIndex, member1);
await client.approveTransaction(multisig, proposal.transactionIndex, member2);
await client.executeTransaction(multisig, proposal.transactionIndex, executor, [
  { pubkey: vault, isSigner: false, isWritable: true },
  { pubkey: recipient, isSigner: false, isWritable: true },
  { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
]);
```

See `sdk/examples/full-flow.ts` for the complete end-to-end example.

## Security

| Property | Mechanism |
|---|---|
| Front-run protection | Multisig PDA is unique per `(members, threshold)`; an attacker initing with different members lands at a different PDA, no relationship to the canonical vault |
| Canonical PDA binding | Anchor `init` seeds = `sha256(sorted_members)`; program verifies `actual_hash == member_hash` — the canonical address can only ever store the canonical member set |
| No deterministic private keys | Pure PDA derivation — no `Keypair::fromSeed` |
| Permissionless init is safe | Init has no signer requirement; funds are gated solely by the threshold check on `create_transaction` / `approve_transaction` / `execute_transaction`. Anyone can pay rent to register the canonical config — they can't subvert it |
| Re-entrancy | `executed = true` is flushed to on-chain data via `Account::exit()` before the CPI loop |
| Threshold enforcement | Approvals are counted on-chain; execute requires `approvals.len() >= threshold` |
| Re-init prevention | Anchor's `init` constraint guarantees the PDA can only be initialized once |
| Account validation | Anchor's seeds + bump constraints + owner check on every account |
| Member-set immutability | `members`, `threshold`, `bump` are written once at init; no instruction can modify them post-init |
| Durable nonce for human-loop signing | `provision_nonce` creates a system-owned nonce account at `createWithSeed(multisigPda, "nonce", SystemProgram)`. Sends after first use `SystemProgram.nonceAdvance` at ix[0] + the nonce value as `recentBlockhash` → wallet's signature survives arbitrary user-approval delays. Address is pure-derivable (paymaster-independent); paymaster rotation transfers authority via standard `SystemProgram.nonceAuthorize` |

## Limits

| Limit | Value | Rationale |
|---|---|---|
| `MAX_MEMBERS` | 30 | Treasury governance + enterprise dual-signing (2 ed25519 keys per SSP signer × 15 signers) |
| `MAX_TX_ACCOUNT_KEYS` | 128 | Static account_keys per proposal |
| `MAX_TX_INSTRUCTIONS` | 16 | Per proposal (CU-limited at execute) |
| `MAX_INSTRUCTION_ACCOUNTS` | 64 | Per instruction (1-byte indexes) |
| `MAX_INSTRUCTION_DATA_LEN` | 1024 | Bytes per instruction |
| `MAX_ADDRESS_TABLE_LOOKUPS` | 4 | ALTs per proposal |
| `MAX_INDEXES_PER_LOOKUP` | 28 | Each (writable + readonly) per ALT |
| `MAX_COMBINED_ACCOUNTS` | 256 | Solana's u8 index space cap |

### Init has no signer ceiling

Init is permissionless — no per-member ed25519 ix is required, so init tx
size is just the program ix itself (~50 bytes + member-set encoding via
ALT). **Any `M-of-N` with `N ≤ 30` and any `threshold ≤ N` can init in a
single tx**, including 30-of-30.

### Single-tx bundled send ceiling

The SSP consumer wallet pattern bundles init (optional) + create + approve×M
+ execute + close into ONE V0 transaction. The bottleneck there is tx-level
signers: each member's ed25519 sig (64 bytes) + their pubkey in the static
section (32 bytes) = ~96 bytes per signer, which cannot be ALT-compressed.
Practical ceiling: **~7 signers per bundled tx** (M=7 single-key OR M=3
dual-key in SSP Enterprise's sol_dual mode). For larger M, the send flow
splits approvals across separate txs (which is the natural model for
multi-party enterprise vaults anyway — each signer on their own device,
signing whenever).

## Build + test

```bash
anchor build              # compile the program
anchor deploy             # deploy (devnet/localnet)
anchor test               # run the test suite
```

Tests live in `tests/`:
- `phase1-basic.ts` — address derivation
- `phase4-unit.ts` — view function unit tests
- `phase4-integration.ts` — permissionless-init flow scenarios (happy paths)
- `phase4-security.ts` — permissionless-init security invariants (canonical PDA binding, front-run resistance, arg validation, re-init rejection)
- `phase5-transactions.ts` — full proposal lifecycle (create / approve / execute)
- `phase6-extra-coverage.ts` — boundary tests + SPL token transfer
- `phase7-close-transaction.ts` — proposal close + rent refund
- `phase8-provision-nonce.ts` — durable nonce account provisioning

Smoke tests against devnet live in `scripts/`:
- `devnet-smoke-test.ts` — basic 3-of-5 SOL flow
- `devnet-spl-smoke-test.ts` — SPL token transfer
- `devnet-large-smoke-test.ts` — 7-of-10 multisig via ALT
- `devnet-decoupled-init-test.ts` — enterprise pattern (paymaster pre-inits with no members online, members operate later)
- `devnet-jupiter-format-test.ts` — Jupiter swap fits proposal format
- `devnet-durable-nonce-test.ts` — durable-nonce flow standalone: provision + bundled send with 90s pause between wallet sign and key sign (no blockhash race)
- `devnet-setup-endpoint-flow-test.ts` — **the current SSP wallet flow**: relay's `/v1/sol/setup` (init + provision_nonce as paymaster-only tx) → then wallet builds the durable-nonce send → 70s pause → key signs → broadcast. End-to-end.
- `devnet-bundled-singletx-test.ts` — *(legacy)* bundled init+create+approve×2+execute+close in ONE V0 tx without nonce. The program still supports it; the current wallet doesn't use this pattern.
- `devnet-first-send-bundled-test.ts` — *(legacy)* bundled init+provision+send in ONE V0 tx. The program still supports it; the current wallet does setup as a separate paymaster tx instead.

## How this differs from Squads V4

The actual program-level differentiators (no UX layers, no infrastructure, just protocol):

1. **Truly self-initiating, permissionlessly** — multisig PDA = `find_program_address([b"multisig", sha256(sorted_members), &[threshold]])`. Anyone can derive the address before any on-chain action, anyone can pre-fund it, and **anyone can register it on-chain** — no member signatures required at init. There is no creator role at any point in the multisig's lifecycle. Squads V4 requires a `creator` who calls `multisig_create_v2` with a random `create_key`; the address is unknowable until creation, and the creator is a single point of trust at setup.

2. **No private key exists, ever** — for a given `(members, threshold)`, the address is purely a function of those inputs hashed into PDA seeds. Same config = same address, deterministically. No creator-supplied randomness, no key generation.

3. **No front-running at init** — different configs produce different PDAs, and `initialize_multisig` binds the PDA to the actual member set at init via the 32-byte hash check (`actual_hash == member_hash`). An attacker initing with different members lands at a different PDA that has no relationship to the canonical vault; an attacker initing with the canonical inputs just pays our rent for us. The canonical address can only ever store the canonical member set.

4. **Threshold enforced only at spend, not at registration** — this mirrors Bitcoin P2WSH (the address IS the hash of the script; anyone can fund it; only valid script-satisfying signatures can spend it). Init has no signer requirement at all; `create_transaction` / `approve_transaction` / `execute_transaction` enforce M-of-N. Permissionless registration is what makes M-of-N enterprise vaults trivial — the relay paymaster can register a vault with no member coordination.

5. **ALT-rejection in proposals** — `create_transaction` rejects non-empty `address_table_lookups`, preventing executor-side ALT substitution attacks where someone could swap a different ALT at execute time to redirect CPI destinations.

### What's not a differentiator

**Fee sponsorship / paymaster** — any wallet on top of any Solana multisig can layer on a paymaster (Squads-using wallets like Fuse, which is built on Squads V4 by Squads Labs, ship comparable sponsored-fee experiences without changing the underlying multisig). SSP Wallet runs a paymaster via the open-source ssp-relay so users don't need SOL in their leaf keypair, but that's a UX choice, not a protocol-level difference.

The program-level differences above are what actually distinguish this design.

## Status

- ✅ Compiles clean (`cargo check`)
- ✅ Devnet deployed (program ID `CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX`, IDL on-chain)
- ✅ End-to-end smoke tests passing on devnet (SOL, SPL, 7-of-10, Jupiter format, bundled single-tx, decoupled-init)
- ✅ Anchor test suite passing in isolated phase runs; multi-phase chained runs are flaky due to local validator load (use `bash scripts/run-tests.sh phase4` etc. per phase)
- ⏳ Mainnet pending (separate keypair; gated on external audit)

## License

MIT
