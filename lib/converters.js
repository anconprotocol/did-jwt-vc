"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.transformPresentationInput = exports.normalizePresentation = exports.transformCredentialInput = exports.normalizeCredential = exports.attestationToVcFormat = exports.isLegacyAttestationFormat = exports.notEmpty = exports.asArray = void 0;
const types_1 = require("./types");
const did_jwt_1 = require("did-jwt");
const additionalPropNames = ['evidence', 'termsOfUse', 'refreshService', 'credentialSchema', 'credentialStatus'];
function asArray(arg) {
    return Array.isArray(arg) ? arg : [arg];
}
exports.asArray = asArray;
function deepCopy(source) {
    return Array.isArray(source)
        ? source.map((item) => deepCopy(item))
        : source instanceof Date
            ? new Date(source.getTime())
            : source && typeof source === 'object'
                ? Object.getOwnPropertyNames(source).reduce((o, prop) => {
                    Object.defineProperty(o, prop, Object.getOwnPropertyDescriptor(source, prop));
                    o[prop] = deepCopy(source[prop]);
                    return o;
                }, Object.create(Object.getPrototypeOf(source)))
                : source;
}
function notEmpty(value) {
    return value !== null && value !== undefined;
}
exports.notEmpty = notEmpty;
function cleanUndefined(input) {
    if (typeof input !== 'object') {
        return input;
    }
    const obj = { ...input };
    Object.keys(obj).forEach((key) => obj[key] === undefined && delete obj[key]);
    return obj;
}
function isLegacyAttestationFormat(payload) {
    return typeof payload === 'object' && payload.sub && payload.iss && payload.claim && payload.iat;
}
exports.isLegacyAttestationFormat = isLegacyAttestationFormat;
function attestationToVcFormat(payload) {
    const { iat, nbf, claim, vc, ...rest } = payload;
    const result = {
        ...rest,
        nbf: nbf ? nbf : iat,
        vc: {
            '@context': [types_1.DEFAULT_CONTEXT],
            type: [types_1.DEFAULT_VC_TYPE],
            credentialSubject: claim,
        },
    };
    if (vc)
        payload.issVc = vc;
    return result;
}
exports.attestationToVcFormat = attestationToVcFormat;
function normalizeJwtCredentialPayload(input, removeOriginalFields = true) {
    let result = deepCopy(input);
    if (isLegacyAttestationFormat(input)) {
        result = attestationToVcFormat(input);
    }
    result.credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject };
    if (input.sub && !input.credentialSubject?.id && result.credentialSubject) {
        result.credentialSubject.id = input.sub;
        if (removeOriginalFields) {
            delete result.sub;
        }
    }
    if (removeOriginalFields) {
        delete result.vc?.credentialSubject;
    }
    if (typeof input.issuer === 'undefined' || typeof input.issuer === 'object') {
        result.issuer = cleanUndefined({ id: input.iss, ...input.issuer });
        if (removeOriginalFields && !input.issuer?.id) {
            delete result.iss;
        }
    }
    if (!input.id && input.jti) {
        result.id = result.id || result.jti;
        if (removeOriginalFields) {
            delete result.jti;
        }
    }
    const types = [...asArray(result.type), ...asArray(result.vc?.type)].filter(notEmpty);
    result.type = [...new Set(types)];
    if (removeOriginalFields) {
        delete result.vc?.type;
    }
    for (const prop of additionalPropNames) {
        if (input.vc && input.vc[prop]) {
            if (!result[prop]) {
                result[prop] = input.vc[prop];
            }
            if (removeOriginalFields) {
                delete result.vc[prop];
            }
        }
    }
    const contextArray = [
        ...asArray(input.context),
        ...asArray(input['@context']),
        ...asArray(input.vc?.['@context']),
    ].filter(notEmpty);
    result['@context'] = [...new Set(contextArray)];
    if (removeOriginalFields) {
        delete result.context;
        delete result.vc?.['@context'];
    }
    if (!input.issuanceDate && (input.iat || input.nbf)) {
        result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString();
        if (removeOriginalFields) {
            if (input.nbf) {
                delete result.nbf;
            }
            else {
                delete result.iat;
            }
        }
    }
    if (!input.expirationDate && input.exp) {
        result.expirationDate = new Date(input.exp * 1000).toISOString();
        if (removeOriginalFields) {
            delete result.exp;
        }
    }
    if (removeOriginalFields) {
        if (result.vc && Object.keys(result.vc).length === 0) {
            delete result.vc;
        }
    }
    return result;
}
function normalizeJwtCredential(input, removeOriginalFields = true) {
    let decoded;
    try {
        decoded = did_jwt_1.decodeJWT(input);
    }
    catch (e) {
        throw new TypeError('unknown credential format');
    }
    return {
        ...normalizeJwtCredentialPayload(decoded.payload, removeOriginalFields),
        proof: {
            type: types_1.DEFAULT_JWT_PROOF_TYPE,
            jwt: input,
        },
    };
}
function normalizeCredential(input, removeOriginalFields = true) {
    if (typeof input === 'string') {
        if (types_1.JWT_FORMAT.test(input)) {
            return normalizeJwtCredential(input, removeOriginalFields);
        }
        else {
            let parsed;
            try {
                parsed = JSON.parse(input);
            }
            catch (e) {
                throw new TypeError('unknown credential format');
            }
            return normalizeCredential(parsed, removeOriginalFields);
        }
    }
    else if (input.proof?.jwt) {
        return deepCopy({ ...normalizeJwtCredential(input.proof.jwt, removeOriginalFields), proof: input.proof });
    }
    else {
        return { proof: {}, ...normalizeJwtCredentialPayload(input, removeOriginalFields) };
    }
}
exports.normalizeCredential = normalizeCredential;
function transformCredentialInput(input, removeOriginalFields = true) {
    if (Array.isArray(input.credentialSubject))
        throw Error('credentialSubject of type array not supported');
    const result = deepCopy({
        vc: { ...input.vc },
        ...input,
    });
    result.vc = result.vc;
    const credentialSubject = { ...input.credentialSubject, ...input.vc?.credentialSubject };
    if (!input.sub) {
        result.sub = input.credentialSubject?.id;
        if (removeOriginalFields) {
            delete credentialSubject.id;
        }
    }
    const contextEntries = [
        ...asArray(input.context),
        ...asArray(input['@context']),
        ...asArray(input.vc?.['@context']),
    ].filter(notEmpty);
    result.vc['@context'] = [...new Set(contextEntries)];
    if (removeOriginalFields) {
        delete result.context;
        delete result['@context'];
    }
    const types = [...asArray(input.type), ...asArray(input.vc?.type)].filter(notEmpty);
    result.vc.type = [...new Set(types)];
    if (removeOriginalFields) {
        delete result.type;
    }
    if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') === -1) {
        result.jti = input.id;
        if (removeOriginalFields) {
            delete result.id;
        }
    }
    if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') === -1) {
        const converted = Date.parse(input.issuanceDate);
        if (!isNaN(converted)) {
            result.nbf = Math.floor(converted / 1000);
            if (removeOriginalFields) {
                delete result.issuanceDate;
            }
        }
    }
    if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') === -1) {
        const converted = Date.parse(input.expirationDate);
        if (!isNaN(converted)) {
            result.exp = Math.floor(converted / 1000);
            if (removeOriginalFields) {
                delete result.expirationDate;
            }
        }
    }
    if (input.issuer && Object.getOwnPropertyNames(input).indexOf('iss') === -1) {
        if (typeof input.issuer === 'object') {
            result.iss = input.issuer?.id;
            if (removeOriginalFields) {
                delete result.issuer.id;
                if (Object.keys(result.issuer).length === 0) {
                    delete result.issuer;
                }
            }
        }
        else if (typeof input.issuer === 'string') {
            result.iss = input.iss || '' + input.issuer;
            if (removeOriginalFields) {
                delete result.issuer;
            }
        }
        else {
        }
    }
    result.vc.credentialSubject = credentialSubject;
    if (removeOriginalFields) {
        delete result.credentialSubject;
    }
    for (const prop of additionalPropNames) {
        if (input[prop]) {
            if (!result.vc[prop]) {
                result.vc[prop] = input[prop];
            }
            if (removeOriginalFields) {
                delete result[prop];
            }
        }
    }
    return result;
}
exports.transformCredentialInput = transformCredentialInput;
function normalizeJwtPresentationPayload(input, removeOriginalFields = true) {
    const result = deepCopy(input);
    result.verifiableCredential = [
        ...asArray(input.verifiableCredential),
        ...asArray(input.vp?.verifiableCredential),
    ].filter(notEmpty);
    result.verifiableCredential = result.verifiableCredential.map((cred) => {
        return normalizeCredential(cred, removeOriginalFields);
    });
    if (removeOriginalFields) {
        delete result.vp?.verifiableCredential;
    }
    if (input.iss && !input.holder) {
        result.holder = input.iss;
        if (removeOriginalFields) {
            delete result.iss;
        }
    }
    if (input.aud) {
        result.verifier = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty);
        result.verifier = [...new Set(result.verifier)];
        if (removeOriginalFields) {
            delete result.aud;
        }
    }
    if (input.jti && Object.getOwnPropertyNames(input).indexOf('id') === -1) {
        result.id = input.id || input.jti;
        if (removeOriginalFields) {
            delete result.jti;
        }
    }
    const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty);
    result.type = [...new Set(types)];
    if (removeOriginalFields) {
        delete result.vp?.type;
    }
    const contexts = [
        ...asArray(input.context),
        ...asArray(input['@context']),
        ...asArray(input.vp?.['@context']),
    ].filter(notEmpty);
    result['@context'] = [...new Set(contexts)];
    if (removeOriginalFields) {
        delete result.context;
        delete result.vp?.['@context'];
    }
    if (!input.issuanceDate && (input.iat || input.nbf)) {
        result.issuanceDate = new Date((input.nbf || input.iat) * 1000).toISOString();
        if (removeOriginalFields) {
            if (input.nbf) {
                delete result.nbf;
            }
            else {
                delete result.iat;
            }
        }
    }
    if (!input.expirationDate && input.exp) {
        result.expirationDate = new Date(input.exp * 1000).toISOString();
        if (removeOriginalFields) {
            delete result.exp;
        }
    }
    if (result.vp && Object.keys(result.vp).length === 0) {
        if (removeOriginalFields) {
            delete result.vp;
        }
    }
    return result;
}
function normalizeJwtPresentation(input, removeOriginalFields = true) {
    let decoded;
    try {
        decoded = did_jwt_1.decodeJWT(input);
    }
    catch (e) {
        throw new TypeError('unknown presentation format');
    }
    return {
        ...normalizeJwtPresentationPayload(decoded.payload, removeOriginalFields),
        proof: {
            type: types_1.DEFAULT_JWT_PROOF_TYPE,
            jwt: input,
        },
    };
}
function normalizePresentation(input, removeOriginalFields = true) {
    if (typeof input === 'string') {
        if (types_1.JWT_FORMAT.test(input)) {
            return normalizeJwtPresentation(input, removeOriginalFields);
        }
        else {
            let parsed;
            try {
                parsed = JSON.parse(input);
            }
            catch (e) {
                throw new TypeError('unknown presentation format');
            }
            return normalizePresentation(parsed, removeOriginalFields);
        }
    }
    else if (input.proof?.jwt) {
        return { ...normalizeJwtPresentation(input.proof.jwt, removeOriginalFields), proof: input.proof };
    }
    else {
        return { proof: {}, ...normalizeJwtPresentationPayload(input, removeOriginalFields) };
    }
}
exports.normalizePresentation = normalizePresentation;
function transformPresentationInput(input, removeOriginalFields = true) {
    const result = deepCopy({
        vp: { ...input.vp },
        ...input,
    });
    result.vp = result.vp;
    const contextEntries = [
        ...asArray(input.context),
        ...asArray(input['@context']),
        ...asArray(input.vp?.['@context']),
    ].filter(notEmpty);
    result.vp['@context'] = [...new Set(contextEntries)];
    if (removeOriginalFields) {
        delete result.context;
        delete result['@context'];
    }
    const types = [...asArray(input.type), ...asArray(input.vp?.type)].filter(notEmpty);
    result.vp.type = [...new Set(types)];
    if (removeOriginalFields) {
        delete result.type;
    }
    if (input.id && Object.getOwnPropertyNames(input).indexOf('jti') === -1) {
        result.jti = input.id;
        if (removeOriginalFields) {
            delete result.id;
        }
    }
    if (input.issuanceDate && Object.getOwnPropertyNames(input).indexOf('nbf') === -1) {
        const converted = Date.parse(input.issuanceDate);
        if (!isNaN(converted)) {
            result.nbf = Math.floor(converted / 1000);
            if (removeOriginalFields) {
                delete result.issuanceDate;
            }
        }
    }
    if (input.expirationDate && Object.getOwnPropertyNames(input).indexOf('exp') === -1) {
        const converted = Date.parse(input.expirationDate);
        if (!isNaN(converted)) {
            result.exp = Math.floor(converted / 1000);
            if (removeOriginalFields) {
                delete result.expirationDate;
            }
        }
    }
    if (result.verifiableCredential || result.vp?.verifiableCredential) {
        result.vp.verifiableCredential = [
            ...asArray(result.verifiableCredential),
            ...asArray(result.vp?.verifiableCredential),
        ]
            .filter(notEmpty)
            .map((credential) => {
            if (typeof credential === 'object' && credential.proof?.jwt) {
                return credential.proof.jwt;
            }
            else {
                return credential;
            }
        });
    }
    if (removeOriginalFields) {
        delete result.verifiableCredential;
    }
    if (input.holder && Object.getOwnPropertyNames(input).indexOf('iss') === -1) {
        if (typeof input.holder === 'string') {
            result.iss = input.holder;
            if (removeOriginalFields) {
                delete result.holder;
            }
        }
        else {
        }
    }
    if (input.verifier) {
        const audience = [...asArray(input.verifier), ...asArray(input.aud)].filter(notEmpty);
        result.aud = [...new Set(audience)];
        if (removeOriginalFields) {
            delete result.verifier;
        }
    }
    return result;
}
exports.transformPresentationInput = transformPresentationInput;
//# sourceMappingURL=converters.js.map