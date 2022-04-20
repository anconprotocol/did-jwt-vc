import { VerifiableCredential, JWT, JwtPresentationPayload, JwtCredentialPayload, CredentialPayload, W3CCredential, Verifiable, PresentationPayload, W3CPresentation } from './types';
export declare function asArray(arg: any | any[]): any[];
export declare function notEmpty<TValue>(value: TValue | null | undefined): value is TValue;
export declare function isLegacyAttestationFormat(payload: Record<string, any>): boolean;
export declare function attestationToVcFormat(payload: Record<string, any>): JwtCredentialPayload;
export declare function normalizeCredential(input: Partial<VerifiableCredential> | Partial<JwtCredentialPayload>, removeOriginalFields?: boolean): Verifiable<W3CCredential>;
declare type DeepPartial<T> = T extends Record<string, unknown> ? {
    [K in keyof T]?: DeepPartial<T[K]>;
} : T;
export declare function transformCredentialInput(input: Partial<CredentialPayload> | DeepPartial<JwtCredentialPayload>, removeOriginalFields?: boolean): JwtCredentialPayload;
export declare function normalizePresentation(input: Partial<PresentationPayload> | DeepPartial<JwtPresentationPayload> | JWT, removeOriginalFields?: boolean): Verifiable<W3CPresentation>;
export declare function transformPresentationInput(input: Partial<PresentationPayload> | DeepPartial<JwtPresentationPayload>, removeOriginalFields?: boolean): JwtPresentationPayload;
export {};
