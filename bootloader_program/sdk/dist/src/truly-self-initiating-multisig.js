"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrulySelfInitiatingMultisig = void 0;
const web3_js_1 = require("@solana/web3.js");
const multisig = __importStar(require("@sqds/multisig"));
const crypto_1 = require("crypto");
const nacl = __importStar(require("tweetnacl"));
const { Permissions } = multisig.types;
/**
 * Truly self-initiating multisig that requires collective approval
 * Eliminates the creator dependency through threshold-based initialization
 */
class TrulySelfInitiatingMultisig {
    constructor(connection, programId = multisig.PROGRAM_ID) {
        this.connection = connection;
        this.programId = programId;
    }
    /**
     * Generate deterministic configuration ID
     */
    generateConfigId(members, threshold, salt) {
        const configData = {
            members: members.map(m => m.toString()).sort(), // Sort for determinism
            threshold,
            salt: salt.toString('hex'),
        };
        const configString = JSON.stringify(configData);
        const hash = (0, crypto_1.createHash)('sha256').update(configString).digest();
        return hash.toString('hex').slice(0, 16); // 16-char ID
    }
    /**
     * Create the message that members must sign to approve initialization
     */
    createApprovalMessage(config, timestamp) {
        const message = {
            action: 'APPROVE_MULTISIG_INITIALIZATION',
            configId: config.configId,
            members: config.members.map(m => m.toString()).sort(),
            threshold: config.threshold,
            salt: config.salt.toString('hex'),
            timeLock: config.timeLock || 0,
            memo: config.memo || '',
            timestamp,
        };
        const messageString = JSON.stringify(message);
        return new TextEncoder().encode(messageString);
    }
    /**
     * Generate deterministic create key from configuration
     */
    deriveCreateKey(members, threshold, salt) {
        const actualSalt = salt || Buffer.from('default-salt');
        const configData = {
            members: members.map(m => m.toString()).sort(),
            threshold,
            salt: actualSalt.toString('hex'),
        };
        const configString = JSON.stringify(configData);
        const configHash = (0, crypto_1.createHash)('sha256').update(configString).digest();
        // Use first 32 bytes of hash as seed for keypair
        const seed = configHash.slice(0, 32);
        return web3_js_1.Keypair.fromSeed(seed);
    }
    /**
     * Derive the multisig address that will be created
     */
    deriveMultisigAddress(members, threshold, salt) {
        const createKey = this.deriveCreateKey(members, threshold, salt);
        const [multisigPda] = multisig.getMultisigPda({
            createKey: createKey.publicKey,
        });
        return multisigPda;
    }
    /**
     * Create an approval signature for multisig initialization
     * Each member must call this to approve the configuration
     */
    async createApproval(config, memberKeypair, timestamp) {
        // Verify the member is authorized
        const memberIsAuthorized = config.members.some(m => m.equals(memberKeypair.publicKey));
        if (!memberIsAuthorized) {
            throw new Error('Member is not authorized for this multisig configuration');
        }
        const approvalTimestamp = timestamp || Date.now();
        const message = this.createApprovalMessage(config, approvalTimestamp);
        // Sign the approval message
        const signature = nacl.sign.detached(message, memberKeypair.secretKey);
        return {
            member: memberKeypair.publicKey,
            signature,
            timestamp: approvalTimestamp,
        };
    }
    /**
     * Verify a member approval signature
     */
    verifyApproval(config, approval) {
        try {
            // Recreate the original message
            const message = this.createApprovalMessage(config, approval.timestamp);
            // Verify signature
            return nacl.sign.detached.verify(message, approval.signature, approval.member.toBytes());
        }
        catch (error) {
            console.error('Signature verification failed:', error);
            return false;
        }
    }
    /**
     * Validate that we have sufficient valid approvals for initialization
     */
    validateApprovals(config, approvals) {
        const errors = [];
        const approvedMembers = [];
        // Check we have enough approvals
        if (approvals.length < config.threshold) {
            errors.push(`Insufficient approvals: need ${config.threshold}, got ${approvals.length}`);
        }
        // Verify each approval
        for (const approval of approvals) {
            // Check member is authorized
            const memberIsAuthorized = config.members.some(m => m.equals(approval.member));
            if (!memberIsAuthorized) {
                errors.push(`Unauthorized member: ${approval.member.toString()}`);
                continue;
            }
            // Check signature is valid
            if (!this.verifyApproval(config, approval)) {
                errors.push(`Invalid signature from member: ${approval.member.toString()}`);
                continue;
            }
            // Check for duplicates
            if (approvedMembers.some(m => m.equals(approval.member))) {
                errors.push(`Duplicate approval from member: ${approval.member.toString()}`);
                continue;
            }
            approvedMembers.push(approval.member);
        }
        // Final validation
        const isValid = errors.length === 0 && approvedMembers.length >= config.threshold;
        return { isValid, approvedMembers, errors };
    }
    /**
     * Initialize multisig using collective approvals (truly self-initiating)
     * Any approved member can execute, but only with proof of collective approval
     */
    async initializeMultisig(config, approvals, executor // Must be one of the approved members
    ) {
        // Validate approvals
        const validation = this.validateApprovals(config, approvals);
        if (!validation.isValid) {
            throw new Error(`Invalid approvals: ${validation.errors.join(', ')}`);
        }
        // Verify executor is one of the approved members
        const executorIsApproved = validation.approvedMembers.some(m => m.equals(executor.publicKey));
        if (!executorIsApproved) {
            throw new Error('Executor must be one of the members who approved initialization');
        }
        console.log(`✅ Collective approval validated: ${validation.approvedMembers.length}/${config.threshold} required signatures verified`);
        console.log(`📋 Approved members: ${validation.approvedMembers.map(m => m.toString().slice(0, 8) + '...').join(', ')}`);
        console.log(`⚡ Executing initialization as: ${executor.publicKey.toString().slice(0, 8)}...`);
        // Get program config for treasury
        const [programConfigPda] = multisig.getProgramConfigPda({});
        const programConfig = await multisig.accounts.ProgramConfig.fromAccountAddress(this.connection, programConfigPda);
        // Generate deterministic createKey
        const createKeyKeypair = this.deriveCreateKey(config.members, config.threshold, config.salt);
        const [multisigPda] = multisig.getMultisigPda({
            createKey: createKeyKeypair.publicKey,
        });
        // Convert members to Squads format
        const squadsMembers = config.members.map(memberKey => ({
            key: memberKey,
            permissions: Permissions.all(),
        }));
        // Execute initialization (executor is just the transaction signer, not the controller)
        const signature = await multisig.rpc.multisigCreateV2({
            connection: this.connection,
            treasury: programConfig.treasury,
            createKey: createKeyKeypair,
            creator: executor, // Executor with collective approval
            multisigPda: multisigPda,
            configAuthority: null,
            threshold: config.threshold,
            members: squadsMembers,
            timeLock: config.timeLock || 0,
            rentCollector: config.rentCollector || null,
            memo: `${config.memo || 'Truly Self-Initiating Multisig'} [Approved by ${validation.approvedMembers.length} members]`,
            sendOptions: { skipPreflight: true }
        });
        // Wait for confirmation
        await this.connection.confirmTransaction(signature, 'confirmed');
        return {
            signature,
            multisigAddress: multisigPda,
            createKey: createKeyKeypair.publicKey,
        };
    }
    /**
     * Check if multisig is already initialized
     */
    async isInitialized(multisigAddress) {
        try {
            await multisig.accounts.Multisig.fromAccountAddress(this.connection, multisigAddress);
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Pre-fund the multisig address before initialization
     */
    async preFund(multisigAddress, funder, amount = 0.01 * web3_js_1.LAMPORTS_PER_SOL) {
        const transaction = new web3_js_1.Transaction().add(web3_js_1.SystemProgram.transfer({
            fromPubkey: funder.publicKey,
            toPubkey: multisigAddress,
            lamports: amount,
        }));
        const signature = await this.connection.sendTransaction(transaction, [funder]);
        await this.connection.confirmTransaction(signature, 'confirmed');
        return signature;
    }
    /**
     * Get current balance of an address
     */
    async getBalance(address) {
        return await this.connection.getBalance(address);
    }
    /**
     * Create initialization configuration object
     */
    createInitializationConfig(members, threshold, options = {}) {
        const salt = options.salt || Buffer.from('default-salt');
        const configId = this.generateConfigId(members, threshold, salt);
        return {
            members,
            threshold,
            salt,
            timeLock: options.timeLock,
            rentCollector: options.rentCollector,
            memo: options.memo,
            configId,
        };
    }
}
exports.TrulySelfInitiatingMultisig = TrulySelfInitiatingMultisig;
exports.default = TrulySelfInitiatingMultisig;
//# sourceMappingURL=truly-self-initiating-multisig.js.map