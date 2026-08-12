# Mainnet Deploy & Upgrade Runbook

Mainnet runs under a **separate program keypair** from devnet, with a staged
upgrade-authority plan: single-sig keypair at launch, transferred to an SSP
enterprise multisig vault (this very program governing itself) once mainnet is
stable.

| | Devnet | Mainnet |
|---|---|---|
| Program ID | `CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX` | `SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r` |
| Build | `anchor build` (default features) | `--features mainnet` (swaps `declare_id!`) |
| Upgrade authority | dev keypair | single-sig → SSP enterprise vault PDA |

The committed SDK IDL (`sdk/src/idl/`) and the IDL parity gate stay on the
**devnet** address — the default build is the canonical IDL source. The SDK
takes the program ID as a constructor argument, so mainnet needs no SDK change;
consumers pass the mainnet ID from their chain config.

## Keys

| Keypair | Where | Notes |
|---|---|---|
| Program keypair | `~/.config/solana/ssp-multisig-mainnet-program.json` | Pubkey **is** the program ID. Needed ONLY for the initial deploy — archive offline (and remove from disk) afterwards. Losing it after deploy costs nothing; leaking it before deploy lets someone squat the address. |
| Upgrade authority | generate at deploy time, e.g. `~/.config/solana/ssp-multisig-mainnet-authority.json` | Deliberate operator action (same philosophy as the mainnet paymaster key — never auto-generated). Keep OFF servers; a Ledger (`usb://ledger`) is preferred if practical. Interim only, until the vault-PDA transfer below. |
| Deployer/payer | any funded keypair | Pays deploy rent + fees — ~5 SOL peak with exact `--max-len` (see funding math in step 2), ~2.4 refunded after deploy. |

## 1. Build (verifiable)

Tag the release commit (`vX.Y.Z`) — the `verifiable-build.yml` workflow builds
both variants in the deterministic docker image and publishes hashes. Locally,
the same build is:

```bash
solana-verify build --library-name solana_multisig -- --features mainnet
solana-verify get-executable-hash target/deploy/solana_multisig.so   # record this
```

Do NOT deploy a plain `anchor build -- --features mainnet` artifact — only the
solana-verify build is reproducible by third parties.

## 2. Deploy

```bash
solana program deploy target/deploy/solana_multisig.so \
  --program-id ~/.config/solana/ssp-multisig-mainnet-program.json \
  --upgrade-authority ~/.config/solana/ssp-multisig-mainnet-authority.json \
  --keypair <deployer.json> \
  --url mainnet-beta \
  --max-len "$(stat -f%z target/deploy/solana_multisig.so)" \
  --with-compute-unit-price 10000 --max-sign-attempts 100
```

`--max-len` at the exact artifact size halves the locked programdata rent
(~2.4 SOL instead of ~4.8 at the default 2× headroom). The trade: before any
upgrade that ships a BIGGER binary, first grow programdata with
`solana program extend <PROGRAM_ID> <extra-bytes> -um` (payer-only — no
authority signature needed, so it stays trivial under vault governance too).
A too-small deploy/upgrade just errors harmlessly; nothing can brick.

Funding math (deployer): peak ≈ buffer rent (~2.4, auto-refunded on close of
the buffer) + programdata rent (~2.4, locked; recoverable only by closing the
program, which destroys the program ID forever) + fees/IDL (~0.05). Fund ~5 SOL,
expect ~2.4 back within minutes of a successful deploy.

A build without `--features mainnet` will deploy but every instruction fails
with `DeclaredProgramIdMismatch` — the loader compares `declare_id!` against
the deployed address. If that happens, rebuild with the feature and redeploy
(upgrade in place, same command).

Then publish the IDL (use the mainnet build's `target/idl`, which carries the
mainnet address):

```bash
anchor idl init SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r \
  --filepath target/idl/solana_multisig.json \
  --provider.cluster mainnet --provider.wallet <deployer.json>
```

## 3. Verify on-chain

```bash
solana-verify verify-from-repo -um \
  --program-id SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r \
  https://github.com/RunOnFlux/solana-multisig \
  --library-name solana_multisig -- --features mainnet
```

Confirm the hash matches the recorded build hash, `solana program show` lists
the expected upgrade authority, and the security.txt surfaces on explorers.

## 4. Smoke test

Real-lamport dry run of the full flow (adapt `scripts/devnet-smoke-test.ts`:
mainnet RPC + mainnet program ID): setup multisig + nonce, propose a minimal
native transfer, approve, execute, and decode via the SDK. Keep amounts dust.

## 5. Upgrades — phase 1 (single-sig authority)

In-place upgrade is just a redeploy signed by the authority:

```bash
solana program deploy target/deploy/solana_multisig.so \
  --program-id SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r \
  --upgrade-authority ~/.config/solana/ssp-multisig-mainnet-authority.json \
  --keypair <deployer.json> --url mainnet-beta
```

Always deploy the solana-verify artifact and re-run step 3 after upgrading.

## 6. Authority transfer — phase 2 (SSP enterprise vault PDA)

Goal: the program's upgrade authority becomes one of its own multisig vault
PDAs (Squads-style self-governance). `execute_transaction` signs arbitrary CPIs
with the vault PDA via `invoke_signed`, which is exactly what the BPF
upgradeable loader requires of an upgrade authority.

1. Create a **dedicated governance vault** on mainnet via the SSP enterprise
   app (do not reuse a treasury vault holding funds), with an M-of-N the org is
   comfortable operating for upgrades. Note its vault PDA.
2. Transfer authority (PDAs cannot co-sign, hence the skip flag):

   ```bash
   solana program set-upgrade-authority SSPWVu7dtTDkZYmDx73StqV46PioSmdiNE7igpjHK1r \
     --upgrade-authority ~/.config/solana/ssp-multisig-mainnet-authority.json \
     --new-upgrade-authority <GOVERNANCE_VAULT_PDA> \
     --skip-new-upgrade-authority-signer-check \
     --url mainnet-beta
   ```

   **This is one-way for the single-sig key** — get the PDA right. Verify with
   `solana program show`.
3. Retire the single-sig authority keypair (archive offline).

Upgrading under vault governance:

1. Write the new artifact to a buffer with any funded keypair:
   `solana program write-buffer target/deploy/solana_multisig.so --url mainnet-beta`
2. Hand the buffer to the vault PDA (the loader requires buffer authority ==
   program upgrade authority at upgrade time):
   `solana program set-buffer-authority <BUFFER> --new-buffer-authority <GOVERNANCE_VAULT_PDA>`
3. Propose an `Upgrade` instruction of `BPFLoaderUpgradeab1e11111111111111111111111`
   in the governance vault, accounts in loader order:
   programdata (writable), program (writable), buffer (writable),
   spill/rent-refund recipient (writable), rent sysvar, clock sysvar,
   vault PDA (signer — supplied by `invoke_signed` at execute).
4. Approve to threshold and execute. Re-verify (step 3 above).

Caveat that must be socialized with every governance-vault member: the vault
PDA now controls program upgrades — the existing "dangerous proposal patterns"
guidance (README) applies doubly. The signing UIs must render loader
instructions clearly before this transfer happens.

## Launch checklist

- [ ] CI green on the release tag (SDK + program + integration dispatch)
- [ ] `verifiable-build.yml` hashes recorded for the tag
- [ ] Program deployed with `--features mainnet` artifact; smoke test passed
- [ ] IDL published on-chain; `solana-verify verify-from-repo` matches
- [ ] Upgrade authority confirmed via `solana program show`; program keypair archived offline
- [ ] READMEs + sdk/README program-ID table updated (remove "coming soon")
- [ ] Ecosystem rollout: `solMainnet` chain configs (relay, relay-enterprise, wallet, key, enterprise app, dashboard) point at this program ID
- [ ] Phase 2 authority transfer scheduled once mainnet is stable
