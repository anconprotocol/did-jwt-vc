"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPresentation = exports.verifyPresentationPayloadOptions = exports.verifyCredential = exports.validatePresentationPayload = exports.validateJwtPresentationPayload = exports.validateCredentialPayload = exports.validateJwtCredentialPayload = exports.createVerifiablePresentationJwt = exports.createVerifiableCredentialJwt = exports.normalizePresentation = exports.normalizeCredential = exports.transformPresentationInput = exports.transformCredentialInput = void 0;
const validators = __importStar(require("./validators"));
const types_1 = require("./types");
const converters_1 = require("./converters");
Object.defineProperty(exports, "transformCredentialInput", { enumerable: true, get: function () { return converters_1.transformCredentialInput; } });
Object.defineProperty(exports, "transformPresentationInput", { enumerable: true, get: function () { return converters_1.transformPresentationInput; } });
Object.defineProperty(exports, "normalizeCredential", { enumerable: true, get: function () { return converters_1.normalizeCredential; } });
Object.defineProperty(exports, "normalizePresentation", { enumerable: true, get: function () { return converters_1.normalizePresentation; } });
const did_jwt_1 = require("did-jwt");
async function createVerifiableCredentialJwt(payload, issuer, options = {}) {
    const parsedPayload = {
        iat: undefined,
        ...converters_1.transformCredentialInput(payload, options.removeOriginalFields),
    };
    validateJwtCredentialPayload(parsedPayload);
    return did_jwt_1.createJWT(parsedPayload, {
        ...options,
        issuer: issuer.did || parsedPayload.iss || '',
        signer: issuer.signer,
    }, {
        ...options.header,
        alg: issuer.alg || options.header?.alg || types_1.JWT_ALG,
    });
}
exports.createVerifiableCredentialJwt = createVerifiableCredentialJwt;
async function createVerifiablePresentationJwt(payload, holder, options = {}) {
    const parsedPayload = {
        iat: undefined,
        ...converters_1.transformPresentationInput(payload, options?.removeOriginalFields),
    };
    if (options.challenge && Object.getOwnPropertyNames(parsedPayload).indexOf('nonce') === -1) {
        parsedPayload.nonce = options.challenge;
    }
    if (options.domain) {
        const audience = [...converters_1.asArray(options.domain), ...converters_1.asArray(parsedPayload.aud)].filter(converters_1.notEmpty);
        parsedPayload.aud = [...new Set(audience)];
    }
    validateJwtPresentationPayload(parsedPayload);
    return did_jwt_1.createJWT(parsedPayload, {
        ...options,
        issuer: holder.did || parsedPayload.iss || '',
        signer: holder.signer,
    }, {
        ...options.header,
        alg: holder.alg || options.header?.alg || types_1.JWT_ALG,
    });
}
exports.createVerifiablePresentationJwt = createVerifiablePresentationJwt;
function validateJwtCredentialPayload(payload) {
    validators.validateContext(payload.vc['@context']);
    validators.validateVcType(payload.vc.type);
    validators.validateCredentialSubject(payload.vc.credentialSubject);
    if (payload.nbf)
        validators.validateTimestamp(payload.nbf);
    if (payload.exp)
        validators.validateTimestamp(payload.exp);
}
exports.validateJwtCredentialPayload = validateJwtCredentialPayload;
function validateCredentialPayload(payload) {
    validators.validateContext(payload['@context']);
    validators.validateVcType(payload.type);
    validators.validateCredentialSubject(payload.credentialSubject);
    if (payload.issuanceDate)
        validators.validateTimestamp(payload.issuanceDate);
    if (payload.expirationDate)
        validators.validateTimestamp(payload.expirationDate);
}
exports.validateCredentialPayload = validateCredentialPayload;
function validateJwtPresentationPayload(payload) {
    validators.validateContext(payload.vp['@context']);
    validators.validateVpType(payload.vp.type);
    if (payload.vp.verifiableCredential && payload.vp.verifiableCredential.length >= 1) {
        for (const vc of converters_1.asArray(payload.vp.verifiableCredential)) {
            if (typeof vc === 'string') {
                validators.validateJwtFormat(vc);
            }
            else {
                validateCredentialPayload(vc);
            }
        }
    }
    if (payload.exp)
        validators.validateTimestamp(payload.exp);
}
exports.validateJwtPresentationPayload = validateJwtPresentationPayload;
function validatePresentationPayload(payload) {
    validators.validateContext(payload['@context']);
    validators.validateVpType(payload.type);
    if (payload.verifiableCredential && payload.verifiableCredential.length >= 1) {
        for (const vc of payload.verifiableCredential) {
            if (typeof vc === 'string') {
                validators.validateJwtFormat(vc);
            }
            else {
                validateCredentialPayload(vc);
            }
        }
    }
    if (payload.expirationDate)
        validators.validateTimestamp(payload.expirationDate);
}
exports.validatePresentationPayload = validatePresentationPayload;
async function verifyCredential(vc, resolver, options = {}) {
    const verified = await did_jwt_1.verifyJWT(vc, { resolver, ...options });
    verified.verifiableCredential = converters_1.normalizeCredential(verified.jwt, options?.removeOriginalFields);
    validateCredentialPayload(verified.verifiableCredential);
    return verified;
}
exports.verifyCredential = verifyCredential;
function verifyPresentationPayloadOptions(payload, options) {
    if (options.challenge && options.challenge !== payload.nonce) {
        throw new Error(`Presentation does not contain the mandatory challenge (JWT: nonce) for : ${options.challenge}`);
    }
    if (options.domain) {
        let matchedAudience;
        if (payload.aud) {
            const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
            matchedAudience = audArray.find((item) => options.domain === item);
        }
        if (typeof matchedAudience === 'undefined') {
            throw new Error(`Presentation does not contain the mandatory domain (JWT: aud) for : ${options.domain}`);
        }
    }
}
exports.verifyPresentationPayloadOptions = verifyPresentationPayloadOptions;
async function verifyPresentation(presentation, resolver, options = {}) {
    const verified = await did_jwt_1.verifyJWT(presentation, { resolver, ...options });
    verifyPresentationPayloadOptions(verified.payload, options);
    verified.verifiablePresentation = converters_1.normalizePresentation(verified.jwt, options?.removeOriginalFields);
    validatePresentationPayload(verified.verifiablePresentation);
    return verified;
}
exports.verifyPresentation = verifyPresentation;
//# sourceMappingURL=index.js.map