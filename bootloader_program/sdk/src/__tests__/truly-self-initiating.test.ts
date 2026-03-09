import { expect } from 'chai';
import { Connection, Keypair, clusterApiUrl, LAMPORTS_PER_SOL } from '@solana/web3.js';
import TrulySelfInitiatingMultisig, { InitializationConfig, MemberApproval } from '../truly-self-initiating-multisig';

describe('TrulySelfInitiatingMultisig', () => {
    let connection: Connection;
    let client: TrulySelfInitiatingMultisig;
    let member1: Keypair;
    let member2: Keypair;
    let member3: Keypair;
    let members: import('@solana/web3.js').PublicKey[];
    let threshold: number;
    let config: InitializationConfig;

    before(async () => {
        connection = new Connection(clusterApiUrl('devnet'), 'confirmed');
        client = new TrulySelfInitiatingMultisig(connection);

        // Generate test members
        member1 = Keypair.generate();
        member2 = Keypair.generate();
        member3 = Keypair.generate();
        members = [member1.publicKey, member2.publicKey, member3.publicKey];
        threshold = 2; // 2-of-3 multisig

        // Create configuration
        config = client.createInitializationConfig(members, threshold, {
            memo: "Test multisig"
        });
    });

    describe('Address Derivation', () => {
        it('should derive deterministic multisig addresses', () => {
            const address1 = client.deriveMultisigAddress(members, threshold);
            const address2 = client.deriveMultisigAddress(members, threshold);
            expect(address1.equals(address2)).to.be.true;
        });

        it('should derive different addresses for different configurations', () => {
            const address1 = client.deriveMultisigAddress(members, threshold);
            const address2 = client.deriveMultisigAddress(members, 3); // Different threshold
            expect(address1.equals(address2)).to.be.false;
        });

        it('should derive consistent create keys', () => {
            const createKey1 = client.deriveCreateKey(members, threshold);
            const createKey2 = client.deriveCreateKey(members, threshold);
            expect(createKey1.publicKey.equals(createKey2.publicKey)).to.be.true;
        });
    });

    describe('Configuration Management', () => {
        it('should create valid initialization config', () => {
            expect(config.members).to.deep.equal(members);
            expect(config.threshold).to.equal(threshold);
            expect(config.configId).to.not.be.undefined;
            expect(config.configId.length).to.equal(16); // 16-char hex ID
        });

        it('should generate deterministic config IDs', () => {
            const config1 = client.createInitializationConfig(members, threshold);
            const config2 = client.createInitializationConfig(members, threshold);
            expect(config1.configId).to.equal(config2.configId);
        });

        it('should generate different config IDs for different configurations', () => {
            const config1 = client.createInitializationConfig(members, threshold);
            const config2 = client.createInitializationConfig(members, 3);
            expect(config1.configId).to.not.equal(config2.configId);
        });
    });

    describe('Member Approvals', () => {
        it('should create valid approval signatures', async () => {
            const approval = await client.createApproval(config, member1);

            expect(approval.member.equals(member1.publicKey)).to.be.true;
            expect(approval.signature).to.be.instanceOf(Uint8Array);
            expect(approval.signature.length).to.equal(64); // ed25519 signature length
            expect(approval.timestamp).to.be.greaterThan(0);
        });

        it('should verify valid approval signatures', async () => {
            const approval = await client.createApproval(config, member1);
            const isValid = client.verifyApproval(config, approval);
            expect(isValid).to.be.true;
        });

        it('should reject invalid approval signatures', async () => {
            const approval = await client.createApproval(config, member1);

            // Tamper with signature
            approval.signature[0] = approval.signature[0] ^ 1;

            const isValid = client.verifyApproval(config, approval);
            expect(isValid).to.be.false;
        });

        it('should reject approvals from unauthorized members', async () => {
            const unauthorizedMember = Keypair.generate();

            try {
                await client.createApproval(config, unauthorizedMember);
                expect.fail('Expected error was not thrown');
            } catch (error) {
                expect(error instanceof Error ? error.message : String(error))
                    .to.include('Member is not authorized for this multisig configuration');
            }
        });

        it('should reject approvals for wrong configuration', async () => {
            const wrongConfig = client.createInitializationConfig([member1.publicKey], 1);
            const approval = await client.createApproval(config, member1);

            const isValid = client.verifyApproval(wrongConfig, approval);
            expect(isValid).to.be.false;
        });
    });

    describe('Approval Validation', () => {
        let approvals: MemberApproval[];

        beforeEach(() => {
            approvals = [];
        });

        it('should validate sufficient approvals', async () => {
            // Get approvals from 2 members (meets threshold)
            approvals.push(await client.createApproval(config, member1));
            approvals.push(await client.createApproval(config, member2));

            const validation = client.validateApprovals(config, approvals);

            expect(validation.isValid).to.be.true;
            expect(validation.approvedMembers).to.have.length(2);
            expect(validation.errors).to.have.length(0);
        });

        it('should reject insufficient approvals', async () => {
            // Only 1 approval, but threshold is 2
            approvals.push(await client.createApproval(config, member1));

            const validation = client.validateApprovals(config, approvals);

            expect(validation.isValid).to.be.false;
            expect(validation.approvedMembers).to.have.length(1);
            expect(validation.errors).to.include('Insufficient approvals: need 2, got 1');
        });

        it('should reject duplicate approvals', async () => {
            const approval1 = await client.createApproval(config, member1);
            const approval2 = await client.createApproval(config, member1); // Same member

            approvals.push(approval1);
            approvals.push(approval2);

            const validation = client.validateApprovals(config, approvals);

            expect(validation.isValid).to.be.false;
            expect(validation.errors.some(e => e.includes('Duplicate approval'))).to.be.true;
        });

        it('should handle mix of valid and invalid approvals', async () => {
            const validApproval = await client.createApproval(config, member1);
            const invalidApproval = await client.createApproval(config, member2);

            // Tamper with second approval
            invalidApproval.signature[0] = invalidApproval.signature[0] ^ 1;

            approvals.push(validApproval);
            approvals.push(invalidApproval);

            const validation = client.validateApprovals(config, approvals);

            expect(validation.isValid).to.be.false;
            expect(validation.approvedMembers).to.have.length(1); // Only valid approval counted
            expect(validation.errors.some(e => e.includes('Invalid signature'))).to.be.true;
        });
    });

    describe('Security Tests', () => {
        it('should prevent initialization with insufficient approvals', async () => {
            const approval = await client.createApproval(config, member1);

            try {
                await client.initializeMultisig(config, [approval], member1);
                expect.fail('Expected error was not thrown');
            } catch (error) {
                expect(error instanceof Error ? error.message : String(error))
                    .to.include('Invalid approvals: Insufficient approvals: need 2, got 1');
            }
        });

        it('should prevent execution by non-approved members', async () => {
            const approval1 = await client.createApproval(config, member1);
            const approval2 = await client.createApproval(config, member2);

            // Try to execute with member3 who didn't approve
            try {
                await client.initializeMultisig(config, [approval1, approval2], member3);
                expect.fail('Expected error was not thrown');
            } catch (error) {
                expect(error instanceof Error ? error.message : String(error))
                    .to.include('Executor must be one of the members who approved initialization');
            }
        });

        it('should prevent execution with tampered approvals', async () => {
            const approval1 = await client.createApproval(config, member1);
            const approval2 = await client.createApproval(config, member2);

            // Tamper with approval
            approval1.signature[0] = approval1.signature[0] ^ 1;

            try {
                await client.initializeMultisig(config, [approval1, approval2], member1);
                expect.fail('Expected error was not thrown');
            } catch (error) {
                expect(error instanceof Error ? error.message : String(error))
                    .to.include('Invalid approvals');
            }
        });
    });

    describe('Deterministic Behavior', () => {
        it('should generate consistent addresses across multiple calls', () => {
            const addresses = [];
            for (let i = 0; i < 10; i++) {
                addresses.push(client.deriveMultisigAddress(members, threshold));
            }

            // All addresses should be identical
            const firstAddress = addresses[0];
            expect(addresses.every(addr => addr.equals(firstAddress))).to.be.true;
        });

        it('should generate consistent config IDs', () => {
            const configs = [];
            for (let i = 0; i < 10; i++) {
                configs.push(client.createInitializationConfig(members, threshold));
            }

            // All config IDs should be identical
            const firstConfigId = configs[0].configId;
            expect(configs.every(config => config.configId === firstConfigId)).to.be.true;
        });

        it('should maintain signature consistency for same timestamp', async () => {
            const timestamp = Date.now();
            const approval1 = await client.createApproval(config, member1, timestamp);
            const approval2 = await client.createApproval(config, member1, timestamp);

            expect(approval1.signature).to.deep.equal(approval2.signature);
            expect(approval1.timestamp).to.equal(approval2.timestamp);
        });
    });

    describe('Edge Cases', () => {
        it('should handle minimum threshold (1-of-1)', async () => {
            const singleMember = [member1.publicKey];
            const singleConfig = client.createInitializationConfig(singleMember, 1);

            const approval = await client.createApproval(singleConfig, member1);
            const validation = client.validateApprovals(singleConfig, [approval]);

            expect(validation.isValid).to.be.true;
            expect(validation.approvedMembers).to.have.length(1);
        });

        it('should handle maximum threshold (n-of-n)', async () => {
            const allRequiredConfig = client.createInitializationConfig(members, 3); // 3-of-3

            const approval1 = await client.createApproval(allRequiredConfig, member1);
            const approval2 = await client.createApproval(allRequiredConfig, member2);
            const approval3 = await client.createApproval(allRequiredConfig, member3);

            const validation = client.validateApprovals(allRequiredConfig, [approval1, approval2, approval3]);

            expect(validation.isValid).to.be.true;
            expect(validation.approvedMembers).to.have.length(3);
        });

        it('should handle empty member list gracefully', () => {
            expect(() => client.createInitializationConfig([], 1))
                .to.not.throw(); // Should create config but validation will fail later
        });

        it('should handle zero threshold gracefully', () => {
            expect(() => client.createInitializationConfig(members, 0))
                .to.not.throw(); // Should create config but validation will fail later
        });
    });

    describe('Real Transaction Tests', () => {
        // Note: These tests require devnet connection and funded accounts
        // They may be skipped in CI environments

        const shouldRunIntegrationTests = process.env.RUN_INTEGRATION_TESTS === 'true';

        (shouldRunIntegrationTests ? it : it.skip)('should successfully initialize multisig with collective approval', async () => {
            // Fund members for transaction fees
            try {
                await Promise.all(members.map(async (member) => {
                    const airdropTx = await connection.requestAirdrop(member, 0.1 * LAMPORTS_PER_SOL);
                    await connection.confirmTransaction(airdropTx, 'confirmed');
                }));
            } catch (error) {
                console.log('Airdrop failed, skipping transaction test');
                return;
            }

            const multisigAddress = client.deriveMultisigAddress(members, threshold);

            // Pre-fund multisig
            await client.preFund(multisigAddress, member1, 0.01 * LAMPORTS_PER_SOL);

            // Get approvals
            const approval1 = await client.createApproval(config, member1);
            const approval2 = await client.createApproval(config, member2);

            // Initialize with collective approval
            const result = await client.initializeMultisig(config, [approval1, approval2], member1);

            expect(result.signature).to.not.be.undefined;
            expect(result.multisigAddress.equals(multisigAddress)).to.be.true;

            // Verify initialization
            const isInitialized = await client.isInitialized(multisigAddress);
            expect(isInitialized).to.be.true;
        }).timeout(30000); // 30 second timeout for blockchain operations
    });
});