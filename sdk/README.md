# @runonflux/solana-multisig

TypeScript SDK for the **SSP Solana Multisig** program — a self-initiating M-of-N multisig on Solana where the multisig address is deterministically derived from `(members, threshold)` and anyone can pre-fund it before initialization.

> **Self-initiating** means: there is no creator/admin role at any point in the multisig's lifecycle. The multisig PDA is fully determined by `(sorted_members, threshold)`, so the canonical address can only ever be registered with the canonical member set. Init is **permissionless** — anyone can pay the rent to register the canonical config — but fund safety is enforced by the M-of-N threshold check on every transaction proposal/approval/execution, never on registration. This mirrors how P2WSH multisig works on Bitcoin: the address IS the hash of the script.

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

// 4. (Optional) ALT for >5 members so each member pubkey costs ~1 byte in the init tx
const alt = await client.createMembersAddressLookupTable(members, payer);

// 5. Submit the init tx — permissionless, no member signatures required
const { multisigAddress, signature } = await client.initialize(
  members,
  threshold,
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
| `createMembersAddressLookupTable(members, payer)` | Create an ALT for member-list compaction (needed for >5 members under the 1232-byte tx cap). |
| `initialize(members, threshold, payer, alt?)` | Submit the permissionless init tx. Anyone can call. |
| `preFund(address, amount, funder)` | Convenience helper to send SOL to a vault. |
| `createTransaction(multisig, vaultIndex, instructions, creator)` | Propose a transaction the multisig should execute. |
| `createTransactionFromMessage(multisig, vaultIndex, message, creator)` | Propose with a pre-built V0 message (for SPL, ALT-using complex flows, etc.). |
| `approveTransaction(multisig, txIndex, member)` | Member approves a pending proposal. |
| `executeTransaction(multisig, txIndex, executor, remainingAccounts)` | Execute once threshold is met. |
| `getMultisig(address)` | Fetch on-chain multisig state. |
| `getTransaction(address)` | Fetch on-chain proposal state. |

### Composable instruction builders (low-level)

For bundling multiple program calls into a single Solana transaction (e.g., for atomic 2-of-2 single-tx send flows), use the ix-only builders. They return raw `TransactionInstruction` objects without sending them, so callers control signing and broadcasting.

| Method | Returns | Use for |
|---|---|---|
| `predictNextTransactionPda(multisig, currentIndex)` | `{ transactionAddress, transactionIndex }` | Compute the next proposal PDA before fetching it on-chain. |
| `buildInitializeMultisigInstruction(opts)` | `{ instruction, multisigAddress, bump }` | Bundle the (permissionless) init ix into a multi-ix tx — e.g. silently included on first send. |
| `buildCreateTransactionInstruction(opts)` | `{ instruction, transactionAddress, transactionIndex }` | Build a proposal ix without auto-sending. |
| `buildApproveTransactionInstruction(opts)` | `TransactionInstruction` | Build an approval ix; member must be a tx-level signer. |
| `buildExecuteTransactionInstruction(opts)` | `TransactionInstruction` | Build an execute ix with explicit `remainingAccounts`. |

Example — 2-of-2 single-tx send (optional permissionless init + create + 2 approvals + execute, signed by both members and broadcast atomically):

```typescript
// Only include the init ix on first send (when the multisig PDA hasn't
// been registered yet). No member signatures needed for init.
const { instruction: initIx, multisigAddress } =
  await client.buildInitializeMultisigInstruction({
    members: [walletPubkey, keyPubkey],
    threshold: 2,
    payer: walletPubkey,
  });

const { instruction: createIx, transactionAddress, transactionIndex } =
  await client.buildCreateTransactionInstruction({
    multisigAddress,
    currentTransactionIndex: 0n, // fresh init → next index is 1
    vaultIndex: 0,
    message: txMessage,
    creator: walletPubkey,
  });

const approveWalletIx = await client.buildApproveTransactionInstruction({
  multisigAddress, transactionAddress, transactionIndex, member: walletPubkey,
});
const approveKeyIx = await client.buildApproveTransactionInstruction({
  multisigAddress, transactionAddress, transactionIndex, member: keyPubkey,
});
const executeIx = await client.buildExecuteTransactionInstruction({
  multisigAddress, transactionAddress, transactionIndex,
  executor: walletPubkey,
  remainingAccounts: [/* in account_keys order */],
});

// Bundle into one tx; both wallet and key partial-sign before broadcast.
const tx = new Transaction().add(
  initIx, createIx, approveWalletIx, approveKeyIx, executeIx,
);
tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
tx.feePayer = walletPubkey;
tx.partialSign(walletKeypair);  // adds wallet's Ed25519 sig
// ... send to key device for partial-signing ...
tx.partialSign(keyKeypair);      // adds key's Ed25519 sig
const sig = await connection.sendRawTransaction(tx.serialize());
```

## Limits

| | Value |
|---|---|
| MAX_MEMBERS | 30 |
| MAX_TX_ACCOUNT_KEYS | 128 |
| MAX_TX_INSTRUCTIONS | 16 |
| MAX_INSTRUCTION_ACCOUNTS | 64 |
| MAX_INSTRUCTION_DATA_LEN | 1024 bytes |

Init has no signer-count ceiling now that it's permissionless (no ed25519 ix to fit in the tx); the cap on members is just the account space.

## Security model

- **No deterministic private keys** — the multisig PDA has no associated keypair. Funds can only move via `(threshold)` member signatures verified on-chain.
- **No creator/admin role** — there is no privileged key controlling the multisig. Self-initiating in the literal sense: the configuration IS the address.
- **Canonical PDA binding** — multisig PDA seeds include the full 32-byte sha256 of sorted members + threshold; the program rejects any init whose `remaining_accounts` don't hash to the `member_hash` argument. The canonical address can only be registered with the canonical member set.
- **Permissionless init is safe** — anyone can pay rent to register the canonical config (front-running it just helps us). They can't subvert the member set; an init with non-canonical members lands at a different PDA that has no relationship to the canonical vault.
- **Threshold gate on every move** — `create_transaction` requires a member signer, `approve_transaction` requires a member signer with dedup, `execute_transaction` requires `approvals.len() ≥ threshold`. Init does not gate funds.
- **No ALT in proposals** — `create_transaction` rejects non-empty `address_table_lookups` in proposal messages, preventing ALT-substitution attacks where an executor swaps a different ALT at execute time.
- **Re-initialization prevented** — `init` constraint guarantees the PDA can only be initialized once.

## Status

- ✅ Devnet deployed
- ✅ End-to-end smoke tests passing on devnet (SOL, SPL, 7-of-10, Jupiter format)
- ✅ 61/61 unit/integration tests passing

## License

MIT
