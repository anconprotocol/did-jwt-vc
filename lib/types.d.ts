import { Signer, JWTVerified, JWTHeader, JWTOptions } from 'did-jwt/src';
export declare const JWT_ALG = "ES256K";
export declare const DID_FORMAT: RegExp;
export declare const JWT_FORMAT: RegExp;
export declare const DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
export declare const DEFAULT_VC_TYPE = "VerifiableCredential";
export declare const DEFAULT_VP_TYPE = "VerifiablePresentation";
export declare const DEFAULT_JWT_PROOF_TYPE = "JwtProof2020";
export declare type JwtCredentialSubject = Record<string, any>;
export interface CredentialStatus {
    id: string;
    type: string;
}
export interface JwtCredentialPayload {
    iss?: string;
    sub?: string;
    vc: Extensible<{
        '@context': string[] | string;
        type: string[] | string;
        credentialSubject: JwtCredentialSubject;
        credentialStatus?: CredentialStatus;
        evidence?: any;
        termsOfUse?: any;
    }>;
    nbf?: number;
    aud?: string | string[];
    exp?: number;
    jti?: string;
    [x: string]: any;
}
export interface JwtPresentationPayload {
    vp: Extensible<{
        '@context': string[] | string;
        type: string[] | string;
        verifiableCredential?: VerifiableCredential[] | VerifiableCredential;
    }>;
    iss?: string;
    aud?: string | string[];
    nbf?: number;
    exp?: number;
    jti?: string;
    nonce?: string;
    [x: string]: any;
}
export declare type IssuerType = Extensible<{
    id: string;
}> | string;
export declare type DateType = string | Date;
interface FixedCredentialPayload {
    '@context': string | string[];
    id?: string;
    type: string | string[];
    issuer: IssuerType;
    issuanceDate: DateType;
    expirationDate?: DateType;
    credentialSubject: Extensible<{
        id?: string;
    }>;
    credentialStatus?: CredentialStatus;
    evidence?: any;
    termsOfUse?: any;
}
export declare type CredentialPayload = Extensible<FixedCredentialPayload>;
interface NarrowCredentialDefinitions {
    '@context': string[];
    type: string[];
    issuer: Exclude<IssuerType, string>;
    issuanceDate: string;
    expirationDate?: string;
}
declare type Replace<T, U> = Omit<T, keyof U> & U;
declare type Extensible<T> = T & {
    [x: string]: any;
};
export declare type W3CCredential = Extensible<Replace<FixedCredentialPayload, NarrowCredentialDefinitions>>;
export interface FixedPresentationPayload {
    '@context': string | string[];
    type: string | string[];
    id?: string;
    verifiableCredential?: VerifiableCredential[];
    holder: string;
    verifier?: string | string[];
    issuanceDate?: string;
    expirationDate?: string;
}
export declare type PresentationPayload = Extensible<FixedPresentationPayload>;
interface NarrowPresentationDefinitions {
    '@context': string[];
    type: string[];
    verifier: string[];
    verifiableCredential?: Verifiable<W3CCredential>[];
}
export declare type W3CPresentation = Extensible<Replace<FixedPresentationPayload, NarrowPresentationDefinitions>>;
export interface Proof {
    type?: string;
    [x: string]: any;
}
export declare type Verifiable<T> = Readonly<T> & {
    readonly proof: Proof;
};
export declare type JWT = string;
export declare type VerifiableCredential = JWT | Verifiable<W3CCredential>;
export declare type VerifiablePresentation = JWT | Verifiable<W3CPresentation>;
export declare type VerifiedJWT = JWTVerified;
export declare type VerifiedPresentation = VerifiedJWT & {
    verifiablePresentation: Verifiable<W3CPresentation>;
};
export declare type VerifiedCredential = VerifiedJWT & {
    verifiableCredential: Verifiable<W3CCredential>;
};
export interface Issuer {
    did: string;
    signer: Signer;
    alg?: string;
}
export interface CreateCredentialOptions extends Partial<JWTOptions> {
    removeOriginalFields?: boolean;
    header?: Partial<JWTHeader>;
    [x: string]: any;
}
export declare type VerifyCredentialOptions = Record<string, any>;
export interface VerifyPresentationOptions extends VerifyCredentialOptions {
    domain?: string;
    challenge?: string;
}
export interface CreatePresentationOptions extends CreateCredentialOptions {
    domain?: string;
    challenge?: string;
}
export {};
