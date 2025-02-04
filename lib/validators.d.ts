import { JwtCredentialSubject, DateType } from './types';
import { VerifiableCredential } from '.';
export declare function validateJwtFormat(value: VerifiableCredential): void;
export declare function validateTimestamp(value: number | DateType): void;
export declare function validateContext(value: string | string[]): void;
export declare function validateVcType(value: string | string[]): void;
export declare function validateVpType(value: string | string[]): void;
export declare function validateCredentialSubject(value: JwtCredentialSubject): void;
