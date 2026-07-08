#!/usr/bin/env bash
# run-tests.sh — orchestrate the integration test suite reliably.
#
# Why this exists: `anchor test` runs all test files in a single mocha
# invocation against a single long-running solana-test-validator. By the
# 50th test the ledger has accumulated enough state that confirmations
# slow past Solana's blockhash-validity window, and tests start failing
# with `TransactionExpiredBlockheightExceededError` despite the underlying
# code being correct.
#
# This script runs each test file against its OWN fresh validator: build
# once, then for each phase spin up a clean validator, deploy, run that
# phase's tests, kill the validator, repeat. Final report aggregates
# results across phases.
#
# Readiness gates per phase (eliminates flakes where the validator answers
# `cluster-version` before it can serve the first tx):
#   1. RPC up                       (`solana cluster-version`)
#   2. Program loaded + executable  (`solana program show <PROGRAM_ID>`)
#   3. Slots advancing              (slot number increased by 3+)
# Only after all three pass does the phase's mocha run start.
#
# Usage:
#   ./scripts/run-tests.sh             # run all phases
#   ./scripts/run-tests.sh phase5      # run only phase5*.ts files
#   SKIP_BUILD=1 ./scripts/run-tests.sh # reuse existing target/deploy
#
# Requirements: anchor 0.31.x, solana-test-validator on PATH.

set -uo pipefail

# Project root (parent of this script's dir)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROGRAM_ID="CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
PROGRAM_SO="$ROOT/target/deploy/solana_multisig.so"
RPC_URL="http://127.0.0.1:8899"
PHASE_FILTER="${1:-}"

PASS=0
FAIL=0
FAILED_PHASES=()

cleanup() {
  if [[ -n "${VALIDATOR_PID:-}" ]] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    kill "$VALIDATOR_PID" 2>/dev/null || true
    # SIGTERM grace then SIGKILL — validator can take a while to flush its
    # ledger to disk on TERM, and we need port 8899 free for the next phase.
    for _ in $(seq 1 10); do
      kill -0 "$VALIDATOR_PID" 2>/dev/null || break
      sleep 1
    done
    kill -9 "$VALIDATOR_PID" 2>/dev/null || true
    wait "$VALIDATOR_PID" 2>/dev/null || true
  fi
  # Wait until port 8899 is actually free before returning (otherwise the
  # next phase's validator may fail to bind, or the OS may queue the
  # previous validator's TIME_WAIT sockets long enough to confuse RPC
  # confirmation timing).
  for _ in $(seq 1 15); do
    if ! lsof -i tcp:8899 -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
}
trap cleanup EXIT INT TERM

# 1. Build (skippable for fast re-runs)
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> anchor build"
  # Pin the SBF platform-tools so CI (fresh Solana install) uses the same rustc
  # as local. Defaults to v1.48 (rustc 1.84.1) — the local default — so this is
  # a no-op outside CI. Override with PLATFORM_TOOLS_VERSION if needed.
  anchor build -- --tools-version "${PLATFORM_TOOLS_VERSION:-v1.48}" || {
    echo "build failed"
    exit 1
  }
fi

if [[ ! -f "$PROGRAM_SO" ]]; then
  echo "missing $PROGRAM_SO — run with SKIP_BUILD=0 or run anchor build first"
  exit 1
fi

# 2. Discover test files
TEST_FILES=()
while IFS= read -r f; do
  if [[ -z "$PHASE_FILTER" || "$f" == *"$PHASE_FILTER"* ]]; then
    TEST_FILES+=("$f")
  fi
done < <(ls "$ROOT/tests"/*.ts | sort)

if [[ ${#TEST_FILES[@]} -eq 0 ]]; then
  echo "no test files matched filter \"$PHASE_FILTER\""
  exit 1
fi

# 3. Run each test file against its own validator
for FILE in "${TEST_FILES[@]}"; do
  PHASE="$(basename "$FILE" .ts)"
  LEDGER_DIR="$(mktemp -d -t ssm-ledger-XXXXXX)"
  VALIDATOR_LOG="$(mktemp -t ssm-validator-XXXXXX)"

  echo
  echo "================================================================"
  echo "== PHASE: $PHASE"
  echo "================================================================"

  # Start fresh validator with the program loaded.
  solana-test-validator \
    --reset \
    --quiet \
    --ledger "$LEDGER_DIR" \
    --bpf-program "$PROGRAM_ID" "$PROGRAM_SO" \
    > "$VALIDATOR_LOG" 2>&1 &
  VALIDATOR_PID=$!

  # Wait for RPC.
  READY=0
  for _ in $(seq 1 30); do
    if solana --url "$RPC_URL" cluster-version >/dev/null 2>&1; then
      READY=1
      break
    fi
    sleep 1
  done
  if [[ $READY -ne 1 ]]; then
    echo "validator failed to start (RPC). log: $VALIDATOR_LOG"
    tail -40 "$VALIDATOR_LOG" || true
    FAIL=$((FAIL + 1))
    FAILED_PHASES+=("$PHASE (validator start)")
    cleanup
    rm -rf "$LEDGER_DIR" "$VALIDATOR_LOG"
    unset VALIDATOR_PID
    continue
  fi

  # Wait for the program to be loaded + executable. RPC may answer
  # `cluster-version` before the BPF program is fully indexed; tests that
  # fire immediately can end up with a blockhash that expires while waiting
  # for the program to become callable. Poll until the program account is
  # both present AND executable.
  PROGRAM_READY=0
  for _ in $(seq 1 30); do
    if solana --url "$RPC_URL" program show "$PROGRAM_ID" 2>/dev/null \
        | grep -q "Authority:"; then
      PROGRAM_READY=1
      break
    fi
    sleep 1
  done
  if [[ $PROGRAM_READY -ne 1 ]]; then
    echo "validator failed to load program $PROGRAM_ID. log: $VALIDATOR_LOG"
    tail -40 "$VALIDATOR_LOG" || true
    FAIL=$((FAIL + 1))
    FAILED_PHASES+=("$PHASE (program not loaded)")
    cleanup
    rm -rf "$LEDGER_DIR" "$VALIDATOR_LOG"
    unset VALIDATOR_PID
    continue
  fi

  # Wait for the validator to actually advance slots — otherwise the first
  # tx's recent_blockhash can be a few slots stale before it even hits the
  # mempool, and confirmation can race the 150-slot expiry window.
  START_SLOT="$(solana --url "$RPC_URL" slot 2>/dev/null || echo 0)"
  SLOT_OK=0
  for _ in $(seq 1 30); do
    NOW_SLOT="$(solana --url "$RPC_URL" slot 2>/dev/null || echo 0)"
    if [[ $NOW_SLOT -gt $((START_SLOT + 3)) ]]; then
      SLOT_OK=1
      break
    fi
    sleep 1
  done
  if [[ $SLOT_OK -ne 1 ]]; then
    echo "validator slot not advancing (still at $START_SLOT)"
    FAIL=$((FAIL + 1))
    FAILED_PHASES+=("$PHASE (slot stalled)")
    cleanup
    rm -rf "$LEDGER_DIR" "$VALIDATOR_LOG"
    unset VALIDATOR_PID
    continue
  fi

  # Run the phase. ts-mocha picks up tsconfig.json automatically.
  set +e
  ANCHOR_PROVIDER_URL="$RPC_URL" \
  ANCHOR_WALLET="$HOME/.config/solana/id.json" \
    yarn run --silent ts-mocha -p ./tsconfig.json -t 120000 "$FILE"
  EXIT=$?
  set -e

  if [[ $EXIT -eq 0 ]]; then
    PASS=$((PASS + 1))
    echo "== $PHASE: OK"
  else
    FAIL=$((FAIL + 1))
    FAILED_PHASES+=("$PHASE (mocha exit $EXIT)")
    echo "== $PHASE: FAIL (exit $EXIT)"
  fi

  cleanup
  unset VALIDATOR_PID
  rm -rf "$LEDGER_DIR" "$VALIDATOR_LOG"
done

echo
echo "================================================================"
echo "== SUMMARY"
echo "================================================================"
echo "phases passed: $PASS"
echo "phases failed: $FAIL"
if [[ ${#FAILED_PHASES[@]} -gt 0 ]]; then
  echo "failures:"
  for p in "${FAILED_PHASES[@]}"; do echo "  - $p"; done
fi

[[ $FAIL -eq 0 ]] || exit 1
