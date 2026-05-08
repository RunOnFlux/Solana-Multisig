# @runonflux/solana-multisig

TypeScript SDK for the **SSP Solana Multisig** program — a self-initiating M-of-N multisig on Solana where the multisig address is deterministically derived from `(members, threshold)` and anyone can pre-fund it before initialization.

> **Self-initiating** means: anyone can derive the multisig address before any on-chain action, anyone can send funds to it, but **only threshold member signatures can initialize it**. There is no "creator" who controls when or whether the multisig is created — the address itself is owned by the cryptographic configuration.

## Install

```sh
yarn add @runonflux/solana-multisig
# or
npm install @runonflux/solana-multisig
```

Peer-ish requirements: `@solana/web3.js`, `@coral-xyz/anchor` (already direct deps; this SDK installs them for you).

## Program IDs

| Network | Program ID |
|---|---|
| Devnet | `CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX` |
| Mainnet | _coming soon_ |

## Quick start

```typescript
import {
  SolanaMultisigClient,
  sortMembers,
} from "@runonflux/solana-multisig";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";

const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX",
);

const connection = new Connection("https://api.devnet.solana.com", "confirmed");
const payer = Keypair.generate();          // funds the init tx
const wallet = new anchor.Wallet(payer);
const client = new SolanaMultisigClient(connection, PROGRAM_ID, wallet);

// 1. Define members + threshold
const members = [m1.publicKey, m2.publicKey, m3.publicKey];
const threshold = 2;

// 2. Derive the multisig + vault addresses (off-chain, free)
const multisig = client.deriveAddress(members, threshold);
const vault = client.deriveVaultAddress(multisig, 0);
console.log("Vault (deposit address):", vault.toBase58());

// 3. Pre-fund the vault (anyone can — vault is just a system PDA)
//    ... user sends SOL to `vault` ...

// 4. Each of `threshold` members signs the init message off-chain
const sigs = [m1, m2].map((m) =>
  client.createSignature(members, threshold, m),
);

// 5. Create an ALT for >5 members (skip for tiny multisigs)
const alt = await client.createMembersAddressLookupTable(members, payer);

// 6. Submit the init tx
const { multisigAddress, signature } = await client.initialize(
  members,
  threshold,
  sigs,
  payer,
  alt,
);
```

After initialization, vault is fully self-custodial — only valid member approvals can move funds out via the proposal flow.

## Proposal flow

```typescript
// Member proposes a transaction
const transferIx = SystemProgram.transfer({
  fromPubkey: vault,
  toPubkey: recipient,
  lamports: 1_000_000,
});

const { transactionAddress, transactionIndex } =
  await client.createTransaction(multisig, 0, [transferIx], creatorKeypair);

// Other members approve until threshold is met
await client.approveTransaction(multisig, transactionIndex, m1);
await client.approveTransaction(multisig, transactionIndex, m2);

// Anyone can execute once threshold reached
await client.executeTransaction(
  multisig,
  transactionIndex,
  executorKeypair,
  [
    { pubkey: vault, isSigner: false, isWritable: true },
    { pubkey: recipient, isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ],
);
```

## SPL token transfers

Vault is a system-owned PDA, so it can hold SPL tokens via standard ATAs. The vault is the token authority for those ATAs.

```typescript
import { createTransferInstruction, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from "@solana/spl-token";

const vaultAta = getAssociatedTokenAddressSync(mint, vault, /* allowOwnerOffCurve */ true);
const recipientAta = getAssociatedTokenAddressSync(mint, recipientOwner);

const transferIx = createTransferInstruction(vaultAta, recipientAta, vault, amount);

// Build a custom V0 message — vault must be account_keys[0]
await client.createTransactionFromMessage(
  multisig,
  /* vaultIndex */ 0,
  {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: 2,
    accountKeys: [vault, vaultAta, recipientAta, TOKEN_PROGRAM_ID],
    instructions: [
      {
        programIdIndex: 3,
        accountIndexes: new Uint8Array([1, 2, 0]), // [source, dest, authority]
        data: new Uint8Array(transferIx.data),
      },
    ],
    addressTableLookups: [],
  },
  creatorKeypair,
);
```

See [`examples/full-flow.ts`](./examples/full-flow.ts) for a complete end-to-end example including init, propose, approve, execute, and SPL token flows.

## API

| Method | Description |
|---|---|
| `deriveAddress(members, threshold)` | Compute the multisig PDA off-chain. |
| `deriveVaultAddress(multisig, vaultIndex)` | Compute the vault PDA (deposit address) off-chain. |
| `createSignature(members, threshold, member)` | Off-chain Ed25519 signature over the init message — one per member. |
| `verifySignatures(members, threshold, sigs)` | Client-side validation before submitting. |
| `createMembersAddressLookupTable(members, payer)` | Create an ALT for member-list compaction (needed for >5 members under the 1232-byte tx cap). |
| `initialize(members, threshold, sigs, payer, alt)` | Submit the init tx with batched Ed25519 verification. |
| `preFund(address, amount, funder)` | Convenience helper to send SOL to a vault. |
| `createTransaction(multisig, vaultIndex, instructions, creator)` | Propose a transaction the multisig should execute. |
| `createTransactionFromMessage(multisig, vaultIndex, message, creator)` | Propose with a pre-built V0 message (for SPL, ALT-using complex flows, etc.). |
| `approveTransaction(multisig, txIndex, member)` | Member approves a pending proposal. |
| `executeTransaction(multisig, txIndex, executor, remainingAccounts)` | Execute once threshold is met. |
| `getMultisig(address)` | Fetch on-chain multisig state. |
| `getTransaction(address)` | Fetch on-chain proposal state. |

## Limits

| | Value |
|---|---|
| MAX_MEMBERS | 20 |
| MAX_TX_ACCOUNT_KEYS | 128 |
| MAX_TX_INSTRUCTIONS | 16 |
| MAX_INSTRUCTION_ACCOUNTS | 64 |
| MAX_INSTRUCTION_DATA_LEN | 1024 bytes |
| Max raw-signature single-tx init (no ALT) | ~5 members |
| Max raw-signature single-tx init (ALT) | 7 members |

For configurations beyond the single-tx ceiling, the client will reject with a clear error.

## Security model

- **No deterministic private keys** — the multisig PDA has no associated keypair. Funds can only move via `(threshold)` member signatures verified on-chain.
- **Self-initiating** — anyone can fund a derived address before init; address is bound to `(members, threshold)` via 32-byte sha256 in the PDA seeds.
- **No ALT in proposals** — `create_transaction` rejects non-empty `address_table_lookups` in proposal messages, preventing ALT-substitution attacks where an executor swaps a different ALT at execute time.
- **Cross-multisig signature replay protected** — init message includes the specific member-set hash, so signatures from one multisig can't be replayed against another.
- **Re-initialization prevented** — `init` constraint guarantees the PDA can only be initialized once.

## Status

- ✅ Devnet deployed
- ✅ End-to-end smoke tests passing on devnet (SOL, SPL, 7-of-10, Jupiter format)
- ✅ 61/61 unit/integration tests passing

## License

MIT
