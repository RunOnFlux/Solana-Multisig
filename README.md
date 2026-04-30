# Truly Self-Initiating Multisig

A Solana multisig program where the multisig address is **deterministically derived from members + threshold**. Anyone can derive the address before any on-chain action; anyone can pre-fund the vault; only threshold member signatures can initialize.

Program ID: `F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo`

## Why "self-initiating"

Standard Solana multisigs (Squads V4 etc.) require a creator account to call `multisig_create_v2` with a random `create_key`. The address is unknowable until creation, and the creator is a single point of trust.

Here, the multisig PDA is derived from `(sorted_members, threshold)` directly:

```
multisig_pda = find_program_address(
  [b"multisig", hash(sorted_members)[..8], &[threshold]],
  program_id
)
```

Implications:
- ✅ Address is knowable BEFORE any on-chain action — pre-fundable
- ✅ No single creator — init requires threshold member signatures
- ✅ Same `(members, threshold)` always yields the same address — no front-run
- ✅ Front-run protection: an attacker with different config derives a different PDA

## Architecture

Two PDA types per multisig:

| PDA | Holds | Owner | Purpose |
|---|---|---|---|
| **Multisig** | members, threshold, tx counter | Our program | Governance / config |
| **Vault** | SOL + SPL tokens (via ATAs) | SystemProgram (no data) | Funds storage |

```
multisig_pda = [b"multisig", hash(members)[..8], &[threshold]]
vault_pda    = [b"vault", multisig_pda, &[vault_index]]   // vault_index 0..255
```

Users send funds TO the vault address. `SystemProgram::transfer` from the vault works because it's system-owned with empty data. Each multisig supports up to 256 vault sub-accounts (most use cases use only `vault_index = 0`).

## Lifecycle

1. **Derive** `(multisig_pda, vault_pda)` off-chain from members + threshold
2. **Pre-fund** the vault address with SOL or SPL (anyone, before init)
3. **Init**: threshold members sign canonical init message off-chain; submit `initialize_multisig` tx with one Ed25519 verify ix per signature preceding the program ix. Multisig PDA is created with config.
4. **Propose**: a member calls `create_transaction(vault_index, message)` storing a V0-style transaction message (header + account_keys + compiled instructions + ALT lookups) on a `VaultTransaction` PDA.
5. **Approve**: each member calls `approve_transaction(index)` once. Approvals accumulate.
6. **Execute**: when approvals ≥ threshold, anyone calls `execute_transaction(index)`. The program flushes `executed = true` (re-entrancy guard), then iterates compiled instructions and CPIs each one with the **vault PDA as signer** via `invoke_signed`.

## Quick start

```typescript
import { TrulySelfInitiatingMultisigClient, deriveVaultAddress } from "@truly-self-initiating/sdk";
import { Connection, PublicKey, SystemProgram } from "@solana/web3.js";

const client = new TrulySelfInitiatingMultisigClient(connection, programId);

// Derive addresses (free, off-chain)
const multisig = client.deriveAddress(members, threshold);
const [vault] = deriveVaultAddress(multisig, 0, programId);

// Pre-fund vault, collect signatures off-chain, then:
await client.initialize(members, threshold, signatures, payer);

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
| Front-run protection | Multisig PDA is unique per `(members, threshold)`; init requires threshold sigs of canonical message |
| No deterministic private keys | Pure PDA derivation — no `Keypair::fromSeed` |
| Init signature replay protection | Ed25519 verification requires `instruction_index = 0xFFFF` (current ix) — prevents binding cryptographic verification to unrelated data |
| Re-entrancy | `executed = true` is flushed to on-chain data via `Account::exit()` before the CPI loop |
| Threshold enforcement | Approvals are counted on-chain; execute requires `approvals.len() >= threshold` |
| Cross-multisig replay | Init signatures bind `(members, threshold)` into the message |
| Account validation | Anchor's seeds + bump constraints + owner check on every account |

## Limits

| Limit | Value | Rationale |
|---|---|---|
| `MAX_MEMBERS` | 20 | Practical for treasury governance |
| `MAX_TX_ACCOUNT_KEYS` | 32 | Static account_keys per proposal |
| `MAX_TX_INSTRUCTIONS` | 16 | Per proposal (CU-limited at execute) |
| `MAX_INSTRUCTION_ACCOUNTS` | 64 | Per instruction (1-byte indexes) |
| `MAX_INSTRUCTION_DATA_LEN` | 1024 | Bytes per instruction |
| `MAX_ADDRESS_TABLE_LOOKUPS` | 4 | ALTs per proposal |
| `MAX_INDEXES_PER_LOOKUP` | 28 | Each (writable + readonly) per ALT |
| `MAX_COMBINED_ACCOUNTS` | 256 | Solana's u8 index space cap |

## Build + test

```bash
anchor build              # compile the program
anchor deploy             # deploy (devnet/localnet)
anchor test               # run the test suite
```

Tests live in `tests/`:
- `phase1-basic.ts` — address derivation
- `phase4-integration.ts` — init flow scenarios (happy paths)
- `phase4-security.ts` — init failure scenarios (attack vectors)
- `phase4-unit.ts` — view function unit tests
- `phase5-transactions.ts` — full proposal lifecycle (create / approve / execute)

## Status

- ✅ Compiles clean (`cargo check`)
- ✅ 5 rounds of internal audit (5 bugs found and fixed)
- ⚠️ No external security audit yet — **commission one before any meaningful TVL**

Suggested audit firms for Solana/Anchor: OtterSec, Neodyme, Halborn. Budget ~$30-50k, timeline 4-8 weeks.

## License

MIT
