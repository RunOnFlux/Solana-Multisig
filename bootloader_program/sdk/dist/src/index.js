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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SquadsPermissions = exports.SquadsPermission = exports.default = exports.TrulySelfInitiatingMultisig = void 0;
// Core client class - Truly Self-Initiating Multisig
var truly_self_initiating_multisig_1 = require("./truly-self-initiating-multisig");
Object.defineProperty(exports, "TrulySelfInitiatingMultisig", { enumerable: true, get: function () { return __importDefault(truly_self_initiating_multisig_1).default; } });
// Default export is the truly self-initiating approach (eliminates creator dependency)
var truly_self_initiating_multisig_2 = require("./truly-self-initiating-multisig");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return __importDefault(truly_self_initiating_multisig_2).default; } });
// Types and interfaces for collective approval
__exportStar(require("./types"), exports);
// Utility functions
__exportStar(require("./utils"), exports);
// Re-export important Squads types for convenience
const multisig = __importStar(require("@sqds/multisig"));
exports.SquadsPermission = multisig.types.Permission;
exports.SquadsPermissions = multisig.types.Permissions;
//# sourceMappingURL=index.js.map