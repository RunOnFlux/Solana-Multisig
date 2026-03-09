"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateMultisigConfig = validateMultisigConfig;
exports.validateSigner = validateSigner;
/**
 * Validates that a multisig configuration is valid
 */
function validateMultisigConfig(members, threshold) {
    // Validate members count first
    if (members.length === 0) {
        throw new Error('At least one member is required');
    }
    if (members.length > 10) {
        throw new Error('Maximum 10 members allowed');
    }
    // Check for duplicate members
    const uniqueMembers = new Set(members.map(m => m.toString()));
    if (uniqueMembers.size !== members.length) {
        throw new Error('Duplicate members in configuration');
    }
    // Validate threshold
    if (threshold <= 0) {
        throw new Error('Threshold must be greater than 0');
    }
    if (threshold > members.length) {
        throw new Error('Threshold cannot exceed number of members');
    }
}
/**
 * Validates that a signer is authorized to initialize the multisig
 */
function validateSigner(signer, members) {
    return members.some(member => member.equals(signer));
}
//# sourceMappingURL=utils.js.map