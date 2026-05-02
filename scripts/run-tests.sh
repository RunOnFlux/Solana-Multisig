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

PROGRAM_ID="F8GiUeVDNuBQWUN5K6HzAzLbWKm2ZASGes4yxG7A6MFo"
PROGRAM_SO="$ROOT/target/deploy/truly_self_initiating_multisig.so"
RPC_URL="http://127.0.0.1:8899"
PHASE_FILTER="${1:-}"

PASS=0
FAIL=0
FAILED_PHASES=()

cleanup() {
  if [[ -n "${VALIDATOR_PID:-}" ]] && kill -0 "$VALIDATOR_PID" 2>/dev/null; then
    kill "$VALIDATOR_PID" 2>/dev/null || true
    wait "$VALIDATOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# 1. Build (skippable for fast re-runs)
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> anchor build"
  anchor build || { echo "build failed"; exit 1; }
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
    echo "validator failed to start. log: $VALIDATOR_LOG"
    tail -40 "$VALIDATOR_LOG" || true
    FAIL=$((FAIL + 1))
    FAILED_PHASES+=("$PHASE (validator start)")
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
