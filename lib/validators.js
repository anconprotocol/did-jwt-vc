"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateCredentialSubject = exports.validateVpType = exports.validateVcType = exports.validateContext = exports.validateTimestamp = exports.validateJwtFormat = void 0;
const types_1 = require("./types");
const converters_1 = require("./converters");
function isDateObject(input) {
    return input && !isNaN(input) && Object.prototype.toString.call(input) === '[object Date]';
}
function validateJwtFormat(value) {
    if (typeof value === 'string' && !value.match(types_1.JWT_FORMAT)) {
        throw new TypeError(`"${value}" is not a valid JWT format`);
    }
}
exports.validateJwtFormat = validateJwtFormat;
function validateTimestamp(value) {
    if (typeof value === 'number') {
        if (!(Number.isInteger(value) && value < 100000000000)) {
            throw new TypeError(`"${value}" is not a unix timestamp in seconds`);
        }
    }
    else if (typeof value === 'string') {
        validateTimestamp(Math.floor(new Date(value).valueOf() / 1000));
    }
    else if (!isDateObject(value)) {
        throw new TypeError(`"${value}" is not a valid time`);
    }
}
exports.validateTimestamp = validateTimestamp;
function validateContext(value) {
    const input = converters_1.asArray(value);
    if (input.length < 1 || input.indexOf(types_1.DEFAULT_CONTEXT) === -1) {
        throw new TypeError(`@context is missing default context "${types_1.DEFAULT_CONTEXT}"`);
    }
}
exports.validateContext = validateContext;
function validateVcType(value) {
    const input = converters_1.asArray(value);
    if (input.length < 1 || input.indexOf(types_1.DEFAULT_VC_TYPE) === -1) {
        throw new TypeError(`type is missing default "${types_1.DEFAULT_VC_TYPE}"`);
    }
}
exports.validateVcType = validateVcType;
function validateVpType(value) {
    const input = converters_1.asArray(value);
    if (input.length < 1 || input.indexOf(types_1.DEFAULT_VP_TYPE) === -1) {
        throw new TypeError(`type is missing default "${types_1.DEFAULT_VP_TYPE}"`);
    }
}
exports.validateVpType = validateVpType;
function validateCredentialSubject(value) {
    if (Object.keys(value).length === 0) {
        throw new TypeError('credentialSubject must not be empty');
    }
}
exports.validateCredentialSubject = validateCredentialSubject;
//# sourceMappingURL=validators.js.map