# Truly Self-Initiating Multisig SDK

A TypeScript SDK for creating truly trustless, deterministic multisig wallets on Solana with **collective approval requirements**. Eliminates the single creator dependency entirely through threshold-based initialization.

## 🔐 Problem Solved

Traditional Squads v4 requires a single-signature "creator" account to initialize multisigs, creating a security vulnerability. This SDK eliminates that dependency by providing:

- **Collective Approval** - requires threshold number of members to approve before initialization
- **Deterministic address generation** before on-chain initialization  
- **No single creator dependency** - multiple members must collectively approve
- **Cryptographic proof** - initialization requires valid signatures from threshold members
- **Full Squads v4 compatibility** - complete access to all Squads features post-initialization

## 🏗️ Architecture Overview

### Collective Approval Process

1. **Approval Collection**: Multiple members sign approval for the configuration
2. **Validation**: Verify threshold number of valid signatures
3. **Execution**: Any approved member can execute with proof of collective approval

This approach eliminates single points of failure during initialization.

```
Members + Threshold + Salt → Config Hash → Deterministic Addresses
                              ↓
                    Collective Member Approvals (off-chain)
                              ↓  
                    Signature Validation + Squads Creation (on-chain)
                              ↓
                      Fully Functional Squads Multisig
```

## 📦 Installation

```bash
npm install @self-initiating-multisig/truly-self-initiating-sdk
```

## 🚀 Quick Start

```typescript
import { Connection, Keypair, LAMPORTS_PER_SOL } from '@solana/web3.js';
import TrulySelfInitiatingMultisig from '@self-initiating-multisig/truly-self-initiating-sdk';

const connection = new Connection("https://api.devnet.solana.com");
const client = new TrulySelfInitiatingMultisig(connection);

// Define your multisig members
const member1 = Keypair.generate();
const member2 = Keypair.generate();
const member3 = Keypair.generate();

const members = [member1.publicKey, member2.publicKey, member3.publicKey];
const threshold = 2; // 2-of-3 multisig

// 1. Create initialization config
const config = client.createInitializationConfig(members, threshold);

// 2. Derive deterministic address  
const multisigAddress = client.deriveMultisigAddress(members, threshold);
console.log("Multisig Address:", multisigAddress.toBase58());

// 3. Optional: Pre-fund the address (possible because it's deterministic)
await client.preFund(multisigAddress, member1, 0.5 * LAMPORTS_PER_SOL);

// 4. Collect member approvals (threshold required)
const approval1 = await client.createApproval(config, member1);
const approval2 = await client.createApproval(config, member2);

// 5. Initialize with collective approval (any approved member can execute)
const result = await client.initializeMultisig(
    config,
    [approval1, approval2],  // Threshold approvals
    member1  // Executor (with proof of collective approval)
);

console.log("Multisig initialized:", result.signature);

// 6. Verify initialization
const isInitialized = await client.isInitialized(multisigAddress);
console.log("Initialized:", isInitialized);
```

## 🔧 Core Features

### Address Derivation

```typescript
// Get just the addresses (for UI, verification, etc.)
const { createKey, multisig, configHash } = await bootloaderClient.deriveAddresses(
    members, 
    threshold,
    salt  // Optional for uniqueness
);

// Get addresses + signing keypair (for initialization)
const { createKeyKeypair, createKey, multisig, configHash } = 
    await bootloaderClient.deriveAddressesAndKeypair(members, threshold, salt);
```

### Pre-funding

```typescript
// Fund the multisig before initialization
await bootloaderClient.preFundMultisig(
    multisigAddress,
    1 * LAMPORTS_PER_SOL,
    funderKeypair
);

// Check balance
const balance = await bootloaderClient.getMultisigBalance(multisigAddress);
console.log(`Balance: ${balance / LAMPORTS_PER_SOL} SOL`);
```

### Multisig Operations

After initialization, use the full Squads v4 feature set:

```typescript
// Create a transaction
const transferInstruction = SystemProgram.transfer({
    fromPubkey: bootloaderClient.getVaultAddress(multisig, 0),
    toPubkey: destinationAddress,
    lamports: 0.1 * LAMPORTS_PER_SOL,
});

const { vaultTxSignature, proposalSignature, transactionIndex } = 
    await bootloaderClient.createTransactionAndProposal(
        multisig,
        [transferInstruction],
        member1,  // Creator
        0,        // Vault index
        "Transfer 0.1 SOL"  // Memo
    );

// Vote on the proposal
await bootloaderClient.approveProposal(multisig, transactionIndex, member1);
await bootloaderClient.approveProposal(multisig, transactionIndex, member2);

// Execute when threshold is reached
await bootloaderClient.executeVaultTransaction(multisig, transactionIndex, member1);
```

## 📋 Complete Example

See [`examples/complete-flow-example.ts`](./examples/complete-flow-example.ts) for a comprehensive demonstration including:

- Deterministic address derivation
- Pre-funding
- Two-step initialization
- Transaction creation and voting
- Execution

## 🧪 Testing

```bash
# Install dependencies
npm install

# Run the example
npm run example:truly-self-init

# Run tests (requires local Solana validator)
npm test
```

### Troubleshooting Devnet Rate Limits

If you encounter airdrop failures due to rate limiting, you can manually fund the accounts:

```bash
# Get the member addresses from the example output, then fund them:
solana airdrop 1 <member1-address> --url devnet
solana airdrop 1 <member2-address> --url devnet  
solana airdrop 1 <member3-address> --url devnet

# Or use the utility script:
npm run fund-accounts <member1-address> <member2-address> <member3-address>
```

### Local Testing Setup

```bash
# Start local validator with Squads v4 program
solana-test-validator \
  --url m \
  --clone-upgradeable-program SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf \
  -c BSTq9w3kZwNwpBXJEvTZz2G9ZTNyKBvoSeXMvwb4cNZr \
  -c Fy3YMJCvwbAXUgUM5b91ucUVA3jYzwWLHL3MwBqKsh8n
```

## 🔍 API Reference

### BootloaderClient

#### Constructor Methods
- `BootloaderClient.create(connection, wallet?)` - Create client instance

#### Address Derivation
- `deriveAddresses(members, threshold, salt?)` - Get deterministic addresses
- `deriveAddressesAndKeypair(members, threshold, salt?)` - Get addresses + keypair

#### Initialization
- `initializeMultisig(params, signer, treasury?)` - Two-step initialization
- `isMultisigInitialized(address)` - Check if initialized

#### Pre-funding
- `preFundMultisig(address, amount, funder)` - Fund before initialization
- `getMultisigBalance(address)` - Check balance

#### Transaction Operations
- `createVaultTransaction(multisig, instructions, creator, vaultIndex?, memo?)` - Create transaction
- `createProposal(multisig, transactionIndex, creator)` - Create proposal
- `createTransactionAndProposal(...)` - Combined creation

#### Voting
- `approveProposal(multisig, transactionIndex, member)` - Approve proposal
- `rejectProposal(multisig, transactionIndex, member)` - Reject proposal

#### Execution
- `executeVaultTransaction(multisig, transactionIndex, member)` - Execute approved transaction

#### Utilities
- `getMultisigInfo(address)` - Get account info
- `getVaultAddress(multisig, index)` - Get vault address
- `getProposalAddress(multisig, transactionIndex)` - Get proposal address

### Utility Functions

```typescript
import { 
    computeConfigHash,
    validateMultisigConfig,
    validateSigner,
    deriveMultisigAddresses,
    deriveCreateKeyKeypair
} from '@self-initiating-multisig/bootloader-sdk';
```

## 🔒 Security Guarantees

- **Deterministic**: Same configuration always produces same addresses
- **Authorization**: Only intended members can initialize
- **Trustless**: No single party controls the initialization process
- **Immutable**: Configuration cannot be changed after hashing
- **Atomic**: Initialization either fully succeeds or fully fails

## 🌐 Network Support

- **Mainnet**: `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`
- **Devnet**: `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`
- **Localnet**: Use program clone commands above

## 🚨 Important Notes

### Squads v4 Integration
This SDK uses the official Squads v4 SDK via RPC calls rather than CPI to avoid Anchor version compatibility issues. This approach:

- ✅ Avoids dependency conflicts
- ✅ Maintains full compatibility
- ✅ Allows independent updates
- ✅ Simplifies testing and deployment

### Key Generation
The `createKey` is generated deterministically from the configuration hash. This ensures:

- Same config always produces same addresses
- Any member can generate the signing keypair
- No coordination needed between parties

### Treasury Requirements
The Squads program requires a treasury account for multisig creation. The SDK automatically fetches this from the Squads program configuration.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [SSP Wallet Integration Guide](./docs/ssp-integration.md)
- **Examples**: [`examples/`](./examples/) directory
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discord**: [SSP Wallet Community](https://discord.gg/sspwallet)

---

**Built for SSP Wallet** - "The most secure wallet out there" 🔐