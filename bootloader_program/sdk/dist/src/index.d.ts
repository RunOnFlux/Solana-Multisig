export { default as TrulySelfInitiatingMultisig } from './truly-self-initiating-multisig';
export { default } from './truly-self-initiating-multisig';
export * from './types';
export * from './utils';
import * as multisig from '@sqds/multisig';
export declare const SquadsPermission: {
    readonly Initiate: 1;
    readonly Vote: 2;
    readonly Execute: 4;
};
export declare const SquadsPermissions: typeof multisig.types.Permissions;
//# sourceMappingURL=index.d.ts.map