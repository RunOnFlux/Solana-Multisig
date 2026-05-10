/**
 * Devnet Jupiter compatibility test (FORMAT VALIDATION ONLY).
 *
 * Jupiter swaps don't execute on devnet (no AMM liquidity), so this test
 * only validates that our proposal format can ACCEPT a real Jupiter swap:
 *
 *   1. Fetch a real Jupiter swap from mainnet API (SOL → USDC, vault as user)
 *   2. Resolve all ALT-referenced accounts to inline pubkeys
 *      (our program rejects proposals with address_table_lookups — Option D
 *      security gate — so Jupiter accounts must fit in static account_keys)
 *   3. Check against program limits: MAX_TX_ACCOUNT_KEYS=128, MAX_INSTRUCTIONS=8,
 *      MAX_IX_DATA_LEN=1024
 *   4. Submit createTransaction on devnet — proves the on-chain message format
 *      accepts a Jupiter-shaped proposal (execution would fail because Jupiter
 *      isn't on devnet, but the proposal-creation path is what we're testing)
 *
 * Run: yarn ts-node scripts/devnet-jupiter-format-test.ts
 */
import * as anchor from "@coral-xyz/anchor";
import {
  AddressLookupTableAccount,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { SolanaMultisigClient } from "../sdk/src";

const DEVNET_RPC = "https://api.devnet.solana.com";
const MAINNET_RPC = "https://api.mainnet-beta.solana.com";
const PROGRAM_ID = new PublicKey(
  "CisPSFTQoTnEqn5cUi1pgpfPp2xiTVRkK7eD5jBevxdX"
);
const DEPLOYER_KEYPAIR_PATH = path.join(os.homedir(), ".config/solana/id.json");

// SOL → USDC, smallest reasonable amount
const SOL_MINT = "So11111111111111111111111111111111111111112";
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SWAP_AMOUNT_LAMPORTS = 1_000_000; // 0.001 SOL
const SLIPPAGE_BPS = 50; // 0.5%

// Limits from lib.rs (must stay in sync — see programs/.../lib.rs constants)
const MAX_TX_ACCOUNT_KEYS = 128;
const MAX_INSTRUCTIONS = 16;
const MAX_IX_DATA_LEN = 1024;

const log = (...args: unknown[]) => console.log(...args);
const sol = (lamports: number) => (lamports / LAMPORTS_PER_SOL).toFixed(6);

interface JupiterAccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}
interface JupiterInstruction {
  programId: string;
  accounts: JupiterAccountMeta[];
  data: string; // base64
}
interface SwapInstructionsResponse {
  tokenLedgerInstruction: JupiterInstruction | null;
  computeBudgetInstructions: JupiterInstruction[];
  setupInstructions: JupiterInstruction[];
  swapInstruction: JupiterInstruction;
  cleanupInstruction: JupiterInstruction | null;
  addressLookupTableAddresses: string[];
}

async function main() {
  const devnetConn = new Connection(DEVNET_RPC, "confirmed");
  const mainnetConn = new Connection(MAINNET_RPC, "confirmed");

  const deployerKey = JSON.parse(
    fs.readFileSync(DEPLOYER_KEYPAIR_PATH, "utf-8")
  );
  const deployer = Keypair.fromSecretKey(Uint8Array.from(deployerKey));
  const wallet = new anchor.Wallet(deployer);
  const client = new SolanaMultisigClient(devnetConn, PROGRAM_ID, wallet);

  log("=== Devnet Jupiter compatibility test (format validation) ===");
  log("Program:", PROGRAM_ID.toBase58());
  log("Deployer:", deployer.publicKey.toBase58());
  const startBalance = await devnetConn.getBalance(deployer.publicKey);
  log("Devnet balance:", sol(startBalance), "SOL");

  // 1. Set up a small 2-of-3 multisig on devnet (cheapest viable config)
  log("\n[1] Setting up 2-of-3 multisig on devnet...");
  const members = Array.from({ length: 3 }, () => Keypair.generate());
  const memberPubkeys = members.map((m) => m.publicKey);
  const threshold = 2;

  const fundTx = new Transaction();
  for (const m of members) {
    fundTx.add(
      SystemProgram.transfer({
        fromPubkey: deployer.publicKey,
        toPubkey: m.publicKey,
        lamports: 0.02 * LAMPORTS_PER_SOL,
      })
    );
  }
  const fundSig = await devnetConn.sendTransaction(fundTx, [deployer]);
  await devnetConn.confirmTransaction(fundSig, "confirmed");

  const multisigAddress = client.deriveAddress(memberPubkeys, threshold);
  const vaultPda = client.deriveVaultAddress(multisigAddress, 0);

  const sigs = members
    .slice(0, threshold)
    .map((m) => client.createSignature(memberPubkeys, threshold, m));
  const alt = await client.createMembersAddressLookupTable(
    memberPubkeys,
    deployer
  );
  await client.initialize(memberPubkeys, threshold, sigs, deployer, alt);
  log("    Multisig:", multisigAddress.toBase58());
  log("    Vault:   ", vaultPda.toBase58());

  // 2. Fetch a real Jupiter swap from mainnet (vault PDA as user)
  log(
    `\n[2] Fetching Jupiter swap from mainnet API: ${
      SWAP_AMOUNT_LAMPORTS / LAMPORTS_PER_SOL
    } SOL → USDC`
  );

  const quoteUrl =
    `https://lite-api.jup.ag/swap/v1/quote?` +
    `inputMint=${SOL_MINT}&outputMint=${USDC_MINT}&` +
    `amount=${SWAP_AMOUNT_LAMPORTS}&slippageBps=${SLIPPAGE_BPS}`;
  const quoteRes = await fetch(quoteUrl);
  if (!quoteRes.ok) {
    throw new Error(
      `Jupiter quote API failed: ${quoteRes.status} ${await quoteRes.text()}`
    );
  }
  const quote = (await quoteRes.json()) as {
    routePlan?: unknown[];
    outAmount?: string;
  };
  log("    Route plan steps:", quote.routePlan?.length ?? 0);
  log("    Output amount:", quote.outAmount, "(raw USDC base units)");

  const swapIxRes = await fetch(
    "https://lite-api.jup.ag/swap/v1/swap-instructions",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quoteResponse: quote,
        userPublicKey: vaultPda.toBase58(),
        wrapAndUnwrapSol: true,
      }),
    }
  );
  if (!swapIxRes.ok) {
    throw new Error(
      `Jupiter swap-instructions API failed: ${
        swapIxRes.status
      } ${await swapIxRes.text()}`
    );
  }
  const swapIxData = (await swapIxRes.json()) as SwapInstructionsResponse;
  log("    Setup ixs:", swapIxData.setupInstructions.length);
  log("    Cleanup ix:", swapIxData.cleanupInstruction ? 1 : 0);
  log("    Compute budget ixs:", swapIxData.computeBudgetInstructions.length);
  log("    ALTs referenced:", swapIxData.addressLookupTableAddresses.length);
  log("    Swap ix accounts:", swapIxData.swapInstruction.accounts.length);
  log(
    "    Swap ix data size:",
    Buffer.from(swapIxData.swapInstruction.data, "base64").length,
    "bytes"
  );

  // 3. Resolve every ALT-referenced account to a concrete pubkey by
  //    fetching the ALTs from mainnet
  log("\n[3] Resolving ALT-referenced accounts via mainnet RPC...");
  const altAccounts: AddressLookupTableAccount[] = [];
  for (const altAddrStr of swapIxData.addressLookupTableAddresses) {
    const altPk = new PublicKey(altAddrStr);
    const altResp = await mainnetConn.getAddressLookupTable(altPk);
    if (!altResp.value) {
      throw new Error(`Could not fetch ALT ${altAddrStr} from mainnet`);
    }
    altAccounts.push(altResp.value);
  }
  const altResolvedPool = new Set<string>();
  altAccounts.forEach((a) =>
    a.state.addresses.forEach((p) => altResolvedPool.add(p.toBase58()))
  );
  log(
    "    ALT addresses pooled:",
    altResolvedPool.size,
    "(any of these may be referenced by the swap)"
  );

  // 4. Collect ONLY the instructions we'll put in the proposal:
  //    setup + swap + cleanup. Skip computeBudget (not part of the multisig
  //    proposal — those are tx-level optimizations).
  const proposalIxs: JupiterInstruction[] = [
    ...swapIxData.setupInstructions,
    swapIxData.swapInstruction,
    ...(swapIxData.cleanupInstruction ? [swapIxData.cleanupInstruction] : []),
  ];
  log(`\n[4] Building proposal with ${proposalIxs.length} instructions`);

  // 5. Build a dedup'd unique-accounts list. Vault must be account_keys[0]
  //    per program invariant. Then all accounts referenced by any instruction.
  const accountSet = new Map<
    string,
    { isSigner: boolean; isWritable: boolean }
  >();
  // Force vault into slot 0
  accountSet.set(vaultPda.toBase58(), {
    isSigner: true,
    isWritable: true,
  });
  for (const ix of proposalIxs) {
    accountSet.set(ix.programId, { isSigner: false, isWritable: false });
    for (const acc of ix.accounts) {
      const existing = accountSet.get(acc.pubkey);
      const isSigner = (existing?.isSigner ?? false) || acc.isSigner;
      const isWritable = (existing?.isWritable ?? false) || acc.isWritable;
      accountSet.set(acc.pubkey, { isSigner, isWritable });
    }
  }

  log("    Total unique accounts:", accountSet.size);
  log("    Limit (MAX_TX_ACCOUNT_KEYS):", MAX_TX_ACCOUNT_KEYS);
  log(
    "    Fits limit:",
    accountSet.size <= MAX_TX_ACCOUNT_KEYS ? "YES ✓" : "NO ✗"
  );

  // Verify per-instruction limits
  let maxIxData = 0;
  for (const ix of proposalIxs) {
    const dataLen = Buffer.from(ix.data, "base64").length;
    if (dataLen > maxIxData) maxIxData = dataLen;
  }
  log(`    Max ix data size: ${maxIxData} / ${MAX_IX_DATA_LEN} bytes`);
  log("    Instruction count:", proposalIxs.length, "/", MAX_INSTRUCTIONS);

  if (accountSet.size > MAX_TX_ACCOUNT_KEYS) {
    log("\n=== JUPITER FORMAT TEST: DOES NOT FIT ===");
    log("The Jupiter swap exceeds MAX_TX_ACCOUNT_KEYS. Would need to either:");
    log(" - Increase the limit (cost: more bytecode)");
    log(" - Or split the swap into multiple proposals");
    return;
  }
  if (proposalIxs.length > MAX_INSTRUCTIONS) {
    log("\n=== JUPITER FORMAT TEST: TOO MANY INSTRUCTIONS ===");
    return;
  }
  if (maxIxData > MAX_IX_DATA_LEN) {
    log("\n=== JUPITER FORMAT TEST: IX DATA TOO LARGE ===");
    return;
  }

  // 6. Compile to V0 message format compatible with our program
  //    Layout:
  //      - account_keys ordered: [signers/writable, signers/readonly,
  //        non-signers/writable, non-signers/readonly]
  //      - vault is at index 0 (signer + writable)
  //    Our program enforces account_keys[0] == vault PDA at vault_index.
  log("\n[5] Compiling proposal message...");

  // Order accounts: signers first (vault), then writable non-signers,
  // then readonly non-signers. Vault is the only signer (everything else
  // either non-signer or, if Jupiter requested signer, we strip — only the
  // vault PDA is a signer in the multisig context).
  const writableNonSigners: string[] = [];
  const readonlyNonSigners: string[] = [];
  for (const [pubkey, meta] of accountSet) {
    if (pubkey === vaultPda.toBase58()) continue; // Already at index 0
    if (meta.isWritable) writableNonSigners.push(pubkey);
    else readonlyNonSigners.push(pubkey);
  }
  const orderedAccountKeys: PublicKey[] = [
    vaultPda,
    ...writableNonSigners.map((p) => new PublicKey(p)),
    ...readonlyNonSigners.map((p) => new PublicKey(p)),
  ];
  const indexOf = (pk: string): number => {
    const idx = orderedAccountKeys.findIndex((k) => k.toBase58() === pk);
    if (idx === -1) throw new Error(`Account not in keys list: ${pk}`);
    return idx;
  };

  const compiledIxs = proposalIxs.map((ix) => ({
    programIdIndex: indexOf(ix.programId),
    accountIndexes: new Uint8Array(
      ix.accounts.map((a) =>
        // If Jupiter wanted the user (vault) as signer, that's slot 0
        // and our program will sign for it via PDA seeds at execute time.
        a.pubkey === vaultPda.toBase58() ? 0 : indexOf(a.pubkey)
      )
    ),
    data: new Uint8Array(Buffer.from(ix.data, "base64")),
  }));

  const message = {
    numSigners: 1,
    numWritableSigners: 1,
    numWritableNonSigners: writableNonSigners.length,
    accountKeys: orderedAccountKeys,
    instructions: compiledIxs,
    addressTableLookups: [], // MUST be empty (Option D security gate)
  };
  log("    Compiled message:");
  log("      account_keys:", message.accountKeys.length);
  log("      instructions:", message.instructions.length);
  log("      numSigners:", message.numSigners);
  log("      numWritableSigners:", message.numWritableSigners);
  log("      numWritableNonSigners:", message.numWritableNonSigners);

  // 7. Submit to devnet — proves on-chain create_transaction accepts the format
  log("\n[6] Submitting createTransaction to devnet...");
  try {
    const createResult = await client.createTransactionFromMessage(
      multisigAddress,
      0,
      message,
      members[0],
      deployer
    );
    log("    Proposal accepted on-chain ✓");
    log("    sig:", createResult.signature);
    log("    proposal index:", createResult.transactionIndex.toString());
    log("    proposal address:", createResult.transactionAddress.toBase58());
  } catch (err) {
    log("    Proposal REJECTED ✗");
    const errAny = err as { message?: string; transactionLogs?: string[] };
    if (errAny.transactionLogs) {
      log("    logs:\n", errAny.transactionLogs.join("\n"));
    } else if (errAny.message) {
      log("    error:", errAny.message);
    } else {
      log("    error:", err);
    }
    throw err;
  }

  const endBalance = await devnetConn.getBalance(deployer.publicKey);
  log("\n=== JUPITER FORMAT TEST PASSED ===");
  log("Total SOL spent:", sol(startBalance - endBalance));
  log(
    `Real Jupiter swap-instructions (SOL→USDC, ${proposalIxs.length} ixs, ${accountSet.size} accounts) fit our proposal format and were accepted by the on-chain create_transaction handler.`
  );
  log(
    "Execution path is not testable on devnet (Jupiter has no AMM liquidity there);"
  );
  log("real end-to-end Jupiter swaps will be validated post-mainnet deploy.");
}

main().catch((err) => {
  console.error("\n!!! JUPITER FORMAT TEST FAILED:");
  console.error(err);
  process.exit(1);
});
