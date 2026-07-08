/**
 * TS ↔ Rust parity tests.
 *
 * These lock the TypeScript SDK to the on-chain Anchor program without needing a
 * validator. They are the CI gate that must stay green before a mainnet push:
 *
 *  1. Instruction/account discriminators in the committed IDL are the canonical
 *     Anchor sighashes (`sha256("global:<name>")[..8]` / `sha256("account:<name>")`),
 *     i.e. exactly what the on-chain program dispatches on.
 *  2. The decoder's HARD-CODED discriminators (the blind-signing protection used
 *     by the wallet / key apps) match the IDL byte-for-byte — the single most
 *     important regression guard: drift here silently breaks tx decoding.
 *  3. Every PDA the SDK derives (multisig / vault / durable nonce) matches the
 *     Rust seed scheme, is member-order independent (Rust sorts members), and is
 *     pinned to a known vector so a derivation change can never pass silently.
 *
 * The Rust side of the parity chain is enforced separately in CI:
 * `anchor build` regenerates the IDL and `scripts/check-idl-parity.mjs` fails if
 * the committed `sdk/src/idl` drifts from the freshly-built program. Together:
 * TS constants == committed IDL == freshly-built IDL == on-chain program.
 */
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { createHash } from "crypto";
import { strict as assert } from "assert";
import { readFileSync } from "fs";
import { join } from "path";
import {
  deriveMultisigAddress,
  deriveVaultAddress,
  deriveNonceAccount,
  sortMembers,
  hashMembers,
} from "../src/utils";
import {
  CREATE_TRANSACTION_DISCRIMINATOR,
  APPROVE_TRANSACTION_DISCRIMINATOR,
  EXECUTE_TRANSACTION_DISCRIMINATOR,
  CLOSE_TRANSACTION_DISCRIMINATOR,
} from "../src/decoder";

// Load the committed IDL via fs (not a JSON import) so the loader is identical
// under ts-node/mocha regardless of Node's ESM JSON-attribute rules.
interface ParityIdl {
  address: string;
  instructions: Array<{ name: string; discriminator: number[] }>;
  accounts: Array<{ name: string; discriminator: number[] }>;
}
const idl: ParityIdl = JSON.parse(
  readFileSync(join(__dirname, "../src/idl/solana_multisig.json"), "utf8")
);

const PROGRAM_ID = new PublicKey(idl.address);
const DEPLOYED_PROGRAM_ID = "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX";

// Anchor derives instruction sighashes as sha256("global:<snake_name>")[..8] and
// account discriminators as sha256("account:<StructName>")[..8]. Recomputing them
// here is the same algorithm the on-chain program uses at dispatch.
function anchorInstructionDiscriminator(name: string): number[] {
  return [
    ...createHash("sha256").update(`global:${name}`).digest().subarray(0, 8),
  ];
}
function anchorAccountDiscriminator(name: string): number[] {
  return [
    ...createHash("sha256").update(`account:${name}`).digest().subarray(0, 8),
  ];
}

describe("parity: program identity", () => {
  it("IDL address is the deployed program id", () => {
    assert.equal(idl.address, DEPLOYED_PROGRAM_ID);
  });
});

describe("parity: instruction discriminators (IDL == Anchor sighash)", () => {
  it("the IDL exposes the full instruction set", () => {
    const names = idl.instructions.map((i) => i.name).sort();
    assert.deepEqual(names, [
      "approve_transaction",
      "close_transaction",
      "create_transaction",
      "derive_address",
      "derive_vault_address",
      "execute_transaction",
      "initialize_multisig",
      "provision_nonce",
    ]);
  });

  for (const ix of idl.instructions) {
    it(`${ix.name}: discriminator == sha256("global:${ix.name}")[..8]`, () => {
      assert.deepEqual(
        ix.discriminator,
        anchorInstructionDiscriminator(ix.name)
      );
    });
  }
});

describe("parity: account discriminators (IDL == Anchor sighash)", () => {
  for (const acc of idl.accounts) {
    it(`${acc.name}: discriminator == sha256("account:${acc.name}")[..8]`, () => {
      assert.deepEqual(acc.discriminator, anchorAccountDiscriminator(acc.name));
    });
  }
});

describe("parity: decoder discriminators == IDL (blind-signing gate)", () => {
  const byName: Record<string, number[]> = {};
  for (const ix of idl.instructions) byName[ix.name] = ix.discriminator;

  const cases: Array<[string, Uint8Array]> = [
    ["create_transaction", CREATE_TRANSACTION_DISCRIMINATOR],
    ["approve_transaction", APPROVE_TRANSACTION_DISCRIMINATOR],
    ["execute_transaction", EXECUTE_TRANSACTION_DISCRIMINATOR],
    ["close_transaction", CLOSE_TRANSACTION_DISCRIMINATOR],
  ];

  for (const [name, constant] of cases) {
    it(`decoder ${name.toUpperCase()}_DISCRIMINATOR matches IDL ${name}`, () => {
      assert.deepEqual([...constant], byName[name]);
    });
  }
});

// Fixed, deterministic member set (valid mainnet pubkeys) for PDA vectors.
const MEMBERS = [
  new PublicKey("11111111111111111111111111111111"),
  new PublicKey("So11111111111111111111111111111111111111112"),
  new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
];
const THRESHOLD = 2;

describe("parity: multisig PDA derivation matches Rust seed scheme", () => {
  // Independent reimplementation of the Rust `derive_multisig_pda`:
  //   find_program_address(["multisig", sha256(concat sorted member bytes), [threshold]], ID)
  // Deriving this a second way (not via the SDK helper) proves the SDK follows
  // the documented Rust scheme rather than merely being self-consistent.
  function referenceMultisigPda(
    members: PublicKey[],
    threshold: number
  ): string {
    const sorted = [...members].sort((a, b) =>
      Buffer.compare(a.toBuffer(), b.toBuffer())
    );
    const h = createHash("sha256");
    for (const m of sorted) h.update(m.toBuffer());
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("multisig"), h.digest(), Buffer.from([threshold])],
      PROGRAM_ID
    );
    return pda.toBase58();
  }

  it("SDK deriveMultisigAddress == independent reference implementation", () => {
    const [pda] = deriveMultisigAddress(MEMBERS, THRESHOLD, PROGRAM_ID);
    assert.equal(pda.toBase58(), referenceMultisigPda(MEMBERS, THRESHOLD));
  });

  it("is member-order independent (Rust hashes sorted members)", () => {
    const [a] = deriveMultisigAddress(MEMBERS, THRESHOLD, PROGRAM_ID);
    const [b] = deriveMultisigAddress(
      [...MEMBERS].reverse(),
      THRESHOLD,
      PROGRAM_ID
    );
    assert.equal(a.toBase58(), b.toBase58());
  });

  it("threshold is part of the seed (different threshold => different PDA)", () => {
    const [t2] = deriveMultisigAddress(MEMBERS, 2, PROGRAM_ID);
    const [t3] = deriveMultisigAddress(MEMBERS, 3, PROGRAM_ID);
    assert.notEqual(t2.toBase58(), t3.toBase58());
  });

  it("is pinned to a known vector (guards against silent derivation changes)", () => {
    const [pda] = deriveMultisigAddress(MEMBERS, THRESHOLD, PROGRAM_ID);
    assert.equal(
      pda.toBase58(),
      "AY4d5iLTYoJuxiyd3k9aXVBWLdbfPuo9FakNRa6hpGxv"
    );
  });
});

describe("parity: vault + durable-nonce derivation", () => {
  const multisig = new PublicKey("So11111111111111111111111111111111111111112");

  it('vault PDA == findProgramAddress(["vault", multisig, [index]])', () => {
    const [sdk] = deriveVaultAddress(multisig, 3, PROGRAM_ID);
    const [ref] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), multisig.toBuffer(), Buffer.from([3])],
      PROGRAM_ID
    );
    assert.equal(sdk.toBase58(), ref.toBase58());
  });

  it('nonce account == createWithSeed(multisig, "nonce", SystemProgram)', async () => {
    const sdk = await deriveNonceAccount(multisig);
    const ref = await PublicKey.createWithSeed(
      multisig,
      "nonce",
      SystemProgram.programId
    );
    assert.equal(sdk.toBase58(), ref.toBase58());
  });
});

describe("parity: member sorting + hashing primitives", () => {
  it("sortMembers is ascending lexicographic by pubkey bytes", () => {
    const sorted = sortMembers(MEMBERS);
    for (let i = 1; i < sorted.length; i++) {
      assert.ok(
        Buffer.compare(sorted[i - 1].toBuffer(), sorted[i].toBuffer()) < 0,
        "members must be strictly ascending by byte order"
      );
    }
  });

  it("hashMembers = sha256 over concatenated member bytes in the given order", () => {
    const sorted = sortMembers(MEMBERS);
    const h = createHash("sha256");
    for (const m of sorted) h.update(m.toBuffer());
    assert.deepEqual(
      Uint8Array.from(hashMembers(sorted)),
      Uint8Array.from(h.digest())
    );
  });
});
