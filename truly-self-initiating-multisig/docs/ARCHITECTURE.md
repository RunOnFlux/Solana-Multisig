# Architecture Overview

## System Design

The Truly Self-Initiating Multisig consists of three layers:

```
┌─────────────────────────────────────────────────────────┐
│                    Client Applications                   │
│           (Web Apps, CLIs, Mobile Apps, etc.)           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  TypeScript SDK Layer                    │
│  • Address Derivation     • Signature Creation          │
│  • Transaction Building   • State Management            │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 Solana Program (Rust)                    │
│  • PDA Derivation        • Signature Verification       │
│  • State Management      • Transaction Execution        │
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Solana Program (On-Chain)

**Purpose**: Enforce security guarantees and manage state

**Key Features**:
- PDA-based address derivation (no private keys)
- On-chain Ed25519 signature verification
- Threshold enforcement
- Transaction proposal and approval system
- Atomic multi-instruction execution

**Account Structure**:

```rust
pub struct Multisig {
    pub members: Vec<Pubkey>,          // Sorted member list
    pub threshold: u8,                  // Required signatures
    pub transaction_index: u64,         // Transaction counter
    pub is_initialized: bool,           // Init flag
    pub bump: u8,                       // PDA bump seed
}

pub struct Transaction {
    pub multisig: Pubkey,              // Parent multisig
    pub index: u64,                     // Transaction number
    pub creator: Pubkey,                // Proposer
    pub instructions: Vec<Instruction>, // Actions to execute
    pub approvers: Vec<Pubkey>,        // Who approved
    pub executed: bool,                 // Execution status
}
```

### 2. TypeScript SDK (Off-Chain)

**Purpose**: Provide developer-friendly interface

**Key Modules**:

#### Client (`client.ts`)
- Main interface for program interaction
- Transaction building and signing
- State queries

#### Utils (`utils.ts`)
- PDA derivation helpers
- Signature creation
- Message formatting
- Validation functions

#### Types (`types.ts`)
- TypeScript interfaces matching on-chain structures
- Type safety for all operations

### 3. Security Model

#### PDA Derivation Strategy

```
Multisig PDA = PDA(
    seeds: [
        b"multisig",
        sha256(sorted_members)[0..8],  // First 8 bytes
        threshold_byte
    ],
    program_id
)
```

**Why This is Secure**:
1. **Deterministic**: Same inputs always give same output
2. **No Private Key**: PDA has no corresponding private key
3. **Unique**: Different configs produce different addresses
4. **Unforgeable**: Cannot manipulate seeds to claim address

#### Signature Verification Flow

```
┌──────────────┐
│  Off-Chain   │
└──────┬───────┘
       │
       │ 1. Member signs message with private key
       │    message = "INIT" || sorted_members || threshold
       │
       ▼
┌──────────────┐
│  Client SDK  │
└──────┬───────┘
       │
       │ 2. Package signature + member pubkey
       │
       ▼
┌──────────────┐
│   On-Chain   │
│   Program    │
└──────┬───────┘
       │
       │ 3. Verify signature on-chain
       │    • Check signer is member
       │    • Verify Ed25519 signature
       │    • Check message hash
       │    • Prevent duplicates
       │
       ▼
┌──────────────┐
│  Initialized │
│   Multisig   │
└──────────────┘
```

## Data Flow

### Initialization Flow

```
1. Configuration
   ├─ Define: members[], threshold
   └─ Compute: multisig_address = derive_pda(members, threshold)

2. Pre-Funding (Optional)
   └─ Transfer: SOL → multisig_address

3. Off-Chain Coordination
   ├─ Member 1: sign(message) → sig1
   ├─ Member 2: sign(message) → sig2
   └─ ...collect threshold signatures

4. On-Chain Initialization
   ├─ Submit: initialize_multisig(members, threshold, signatures)
   ├─ Verify: All signatures valid
   ├─ Check: Threshold met
   └─ Create: Multisig account

5. Ready
   └─ Multisig operational and secure
```

### Transaction Execution Flow

```
1. Proposal
   ├─ Member creates: Instructions[]
   └─ Submit: create_transaction(instructions)

2. Approval Phase
   ├─ Member 1: approve_transaction(tx_index)
   ├─ Member 2: approve_transaction(tx_index)
   └─ ...until threshold met

3. Execution
   ├─ Check: Threshold approvals?
   ├─ Execute: All instructions atomically
   └─ Mark: Transaction as executed
```

## Security Properties

### Guaranteed Properties

| Property | Guarantee | How It's Enforced |
|----------|-----------|-------------------|
| **Determinism** | Same config → same address | PDA seeds from sorted members |
| **No Private Keys** | No one can sign as multisig | PDA has no private key |
| **Threshold** | Requires N signatures | On-chain counter check |
| **Member Authorization** | Only members control | Member list verification |
| **Front-Run Protection** | Can't steal pre-funded address | Different config = different PDA |
| **Re-init Prevention** | Can't reinitialize | Account already exists check |
| **Atomicity** | All-or-nothing execution | Solana transaction guarantees |

### Attack Surface Analysis

#### Eliminated Attacks
- ❌ Front-running (no private key to steal)
- ❌ Signature forgery (Ed25519 verification)
- ❌ Threshold bypass (on-chain enforcement)
- ❌ Unauthorized initialization (member check)
- ❌ Re-initialization (account exists check)

#### Remaining Risks
- ⚠️ **Member Key Compromise**: If threshold members' keys are compromised, multisig is compromised
  - Mitigation: Use hardware wallets, key rotation (future feature)
- ⚠️ **Social Engineering**: Members could be tricked into signing
  - Mitigation: Display clear signing messages, confirmation flows
- ⚠️ **Program Upgrade**: Upgrade authority could modify program
  - Mitigation: Transfer to governance, time-locks on upgrades

## Performance Characteristics

### Costs (Approximate)

| Operation | Cost (SOL) | Notes |
|-----------|------------|-------|
| Initialize Multisig | ~0.002 | Rent + tx fee |
| Create Transaction | ~0.001 | Per proposal |
| Approve Transaction | ~0.0001 | Per approval |
| Execute Transaction | ~0.0001 + fees | Plus instruction fees |

### Limits

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Max Members | 10 | Account size constraint |
| Max Instructions/TX | 8 | Complexity management |
| Max Accounts/Instruction | 20 | Transaction size limit |
| Max Instruction Data | 1024 bytes | Safety margin |

### Scalability

**Transaction Throughput**: Limited by Solana network capacity (~65,000 TPS theoretical)

**Storage**: Each multisig account ~500 bytes

**Concurrent Operations**: Multiple transactions can be proposed/approved in parallel

## Comparison with Alternatives

### vs. Traditional Squads

| Feature | Squads | Truly Self-Initiating |
|---------|--------|----------------------|
| Creator Required | ✅ Yes | ❌ No |
| Pre-Funding Safe | ❌ No | ✅ Yes |
| Deterministic Address | ⚠️ After creation | ✅ Before creation |
| Front-Run Risk | ⚠️ Possible | ✅ Impossible |
| Threshold Enforcement | ✅ On-chain | ✅ On-chain |

### vs. Gnosis Safe (EVM)

| Feature | Gnosis Safe | Truly Self-Initiating |
|---------|-------------|----------------------|
| Blockchain | Ethereum/EVM | Solana |
| Gas Costs | High ($10-100) | Low ($0.001-0.01) |
| Speed | 12-15 seconds | 400ms |
| Pre-Funding | ⚠️ Contract deployment needed | ✅ Before initialization |
| Security Model | Contract-based | PDA-based |

## Future Enhancements

### Phase 6: Advanced Features (Roadmap)

1. **Time Locks**
   - Delayed execution for high-value transactions
   - Emergency cancellation windows

2. **Transaction Scheduling**
   - Scheduled execution at future timestamps
   - Recurring transactions

3. **Spending Limits**
   - Per-member or per-period limits
   - Automatic approval for small amounts

4. **Key Rotation**
   - Replace members without changing address
   - Threshold adjustment

5. **Plugin System**
   - Custom validation logic
   - Integration with other protocols

6. **Multi-Asset Support**
   - SPL tokens
   - NFTs
   - Other Solana assets

7. **Sub-Multisigs**
   - Hierarchical multisig structures
   - Delegation patterns

## Deployment Considerations

### Network Selection

**Localnet**: Development and testing
**Devnet**: Integration testing and demos
**Mainnet**: Production use

### Monitoring

Recommended metrics to track:
- Transaction approval times
- Failed transaction rate
- Member participation rates
- Treasury balance changes
- Gas costs per operation

### Upgrade Strategy

1. **Development**: Test on localnet
2. **Staging**: Deploy to devnet, run integration tests
3. **Audit**: Security review of changes
4. **Mainnet Deployment**: 
   - Deploy with upgrade authority
   - Monitor for issues
   - Transfer authority to governance after stabilization

## Conclusion

The Truly Self-Initiating Multisig provides a secure, efficient, and truly decentralized multisig solution for Solana. Its architecture eliminates single points of failure while maintaining usability and performance.

