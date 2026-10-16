# Changelog — @runonflux/solana-multisig (SDK)

## 0.12.1

Security hardening of the signing-device decoder (SSP security review 2026-10).
The on-chain program is unchanged.

### Changed (fail-closed, may reject bundles that were accepted before)

- **Legacy SPL `Transfer` (tag 3) is refused** (SOL-5 / CHN-3). It carries no
  mint, so the moved token could not be bound to what is displayed. It is now
  counted in `unknownInnerInstructionCount` instead of being returned as a
  recipient. Both SSP builders emit `TransferChecked` only.
- `compareDecodedToExpected` **binds the asset**: with `tokenMint`, every
  decoded recipient must be a `TransferChecked` of exactly that mint; without
  it, every recipient must be native SOL. New optional `tokenDecimals` must
  equal the on-the-wire decimals.
- New optional `expectedMultisigPda`, `expectedVaultIndex`, `expectedVaultPda`
  in `compareDecodedToExpected` (SOL-7): the relay can no longer substitute
  another vault the signer is a member of when the caller passes the locally
  derived multisig.
- Approve-only bundles: every approve must target the same proposal of the
  same multisig; the approve's `transactionIndex` and `approveMultisigs` are
  now returned.
- Amount and fee-cap strings must be plain non-negative integers (`""` no
  longer parses as 0).

### Added

- `fetchAndDecodeProposal`, `decodeVaultTransactionAccount`,
  `compareProposalToExpected` and `verifyApproveOnlyTransaction` (H-13 /
  SOL-3 / CHN-4): verify an approve-only request against the on-chain
  `VaultTransaction` (owner, discriminator, canonical PDA, not executed,
  expected multisig, stored fund flows).
- `verifyConsumerSolanaBundle` (C-3 / SOL-1): a fail-closed gate for the
  consumer 2-of-2 send bundle (exactly one create, distinct member approvals,
  every multisig instruction bound to the locally derived multisig, fee payer
  not a member, capped ComputeBudget, ATA create only for the recipient,
  inner message limited to the expected transfer + capped fee + Memo v2).
- `decodeVaultSolanaTransaction` options `allowComputeBudget` (capped
  SetComputeUnitLimit/SetComputeUnitPrice, needed for mainnet bundles that
  carry a priority fee) and `allowMemo` (Memo v2 without accounts). Both are
  off by default, which keeps the previous behaviour.
- Recipients carry `tokenProgram`; the comparison matches a recipient owner
  through its derived ATA.
- Exported `COMPUTE_BUDGET_PROGRAM_ID`, `MEMO_PROGRAM_ID`,
  `VAULT_TRANSACTION_ACCOUNT_DISCRIMINATOR`, `ExpectedSolanaVaultPayload`,
  `SolanaConnectionLike`.
