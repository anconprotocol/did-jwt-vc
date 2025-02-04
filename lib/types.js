"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_JWT_PROOF_TYPE = exports.DEFAULT_VP_TYPE = exports.DEFAULT_VC_TYPE = exports.DEFAULT_CONTEXT = exports.JWT_FORMAT = exports.DID_FORMAT = exports.JWT_ALG = void 0;
exports.JWT_ALG = 'ES256K';
exports.DID_FORMAT = /^did:([a-zA-Z0-9_]+):([:[a-zA-Z0-9_.-]+)(\/[^#]*)?(#.*)?$/;
exports.JWT_FORMAT = /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;
exports.DEFAULT_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
exports.DEFAULT_VC_TYPE = 'VerifiableCredential';
exports.DEFAULT_VP_TYPE = 'VerifiablePresentation';
exports.DEFAULT_JWT_PROOF_TYPE = 'JwtProof2020';
//# sourceMappingURL=types.js.map