// Core client class - Truly Self-Initiating Multisig
export { default as TrulySelfInitiatingMultisig } from './truly-self-initiating-multisig';

// Default export is the truly self-initiating approach (eliminates creator dependency)
export { default } from './truly-self-initiating-multisig';

// Types and interfaces for collective approval
export * from './types';

// Utility functions
export * from './utils';

// Re-export important Squads types for convenience
import * as multisig from '@sqds/multisig';
export const SquadsPermission = multisig.types.Permission;
export const SquadsPermissions = multisig.types.Permissions;