#!/usr/bin/env node
/**
 * IDL parity gate (the Rust side of TS↔Rust parity).
 *
 * `anchor build` regenerates target/idl/solana_multisig.json from the on-chain
 * program. This script fails if the IDL committed at sdk/src/idl/ has drifted
 * from that freshly-built IDL on any field the SDK depends on: the program
 * address and every instruction/account discriminator. Combined with the SDK
 * parity tests (which assert TS constants == committed IDL), this closes the
 * chain: TS decoder/derivations == committed IDL == built program == on-chain.
 *
 * Compares SEMANTICS, not formatting, so a whitespace/key-order difference in
 * the generated JSON never causes a false failure.
 *
 * Usage (run from repo root, after `anchor build`):
 *   node scripts/check-idl-parity.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUILT = join(root, "target/idl/solana_multisig.json");
const COMMITTED = join(root, "sdk/src/idl/solana_multisig.json");

function load(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    console.error(`Could not read ${label} IDL at ${path}: ${e.message}`);
    if (label === "built") {
      console.error("Run `anchor build` first so target/idl exists.");
    }
    process.exit(2);
  }
}

// Reduce an IDL to just the fields the SDK is coupled to.
function semantics(idl) {
  const discMap = (arr) =>
    Object.fromEntries(
      (arr || []).map((x) => [x.name, (x.discriminator || []).join(",")])
    );
  return {
    address: idl.address,
    instructions: discMap(idl.instructions),
    accounts: discMap(idl.accounts),
  };
}

const built = semantics(load(BUILT, "built"));
const committed = semantics(load(COMMITTED, "committed"));

const diffs = [];
if (built.address !== committed.address) {
  diffs.push(
    `program address: built=${built.address} committed=${committed.address}`
  );
}
for (const kind of ["instructions", "accounts"]) {
  const names = new Set([
    ...Object.keys(built[kind]),
    ...Object.keys(committed[kind]),
  ]);
  for (const name of [...names].sort()) {
    const b = built[kind][name];
    const c = committed[kind][name];
    if (b !== c) {
      diffs.push(
        `${kind.slice(0, -1)} "${name}": built=[${b ?? "MISSING"}] committed=[${c ?? "MISSING"}]`
      );
    }
  }
}

if (diffs.length > 0) {
  console.error("IDL PARITY DRIFT — committed sdk/src/idl is stale vs the built program:");
  for (const d of diffs) console.error("  - " + d);
  console.error(
    "\nFix: copy target/idl/solana_multisig.json to sdk/src/idl/solana_multisig.json,"
  );
  console.error(
    "update the decoder discriminators if any changed, and re-run the SDK parity tests."
  );
  process.exit(1);
}

const ixCount = Object.keys(committed.instructions).length;
const accCount = Object.keys(committed.accounts).length;
console.log(
  `IDL parity OK — committed SDK IDL matches the built program ` +
    `(address + ${ixCount} instruction and ${accCount} account discriminators).`
);
