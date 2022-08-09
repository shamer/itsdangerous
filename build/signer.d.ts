/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
export declare class BadSignatureError extends Error {
}
export declare class UnknownKeyDerivationError extends Error {
}
export declare class UnimplementedError extends Error {
}
declare type BinaryLike = string | NodeJS.ArrayBufferView;
declare type DigestMethod = (data: BinaryLike) => NodeJS.ArrayBufferView;
interface SigningAlgorithm {
    sign(key: BinaryLike, value: BinaryLike): NodeJS.ArrayBufferView;
    verify(sig: BinaryLike, value: BinaryLike, key: BinaryLike): boolean;
}
export declare enum KeyDerivation {
    Concat = "concat",
    DjangoConcat = "django-concat",
    HMAC = "hmac",
    None = "none"
}
export declare const defaultDigestMethod: (data: BinaryLike) => NodeJS.ArrayBufferView;
export declare class Signer {
    salt: string;
    secretKey: string;
    separator: string;
    keyDerivation: KeyDerivation;
    digestMethod: DigestMethod;
    signingAlgorithm: SigningAlgorithm;
    constructor(args: {
        secretKey: string;
        salt?: string;
        separator?: string;
        digestMethod?: DigestMethod;
        keyDerivation?: KeyDerivation;
        signingAlgorithm?: SigningAlgorithm;
    });
    deriveKey(secretKey?: string): NodeJS.ArrayBufferView;
    sign(msg: string): string;
    unsign(signedMsg: string): string;
}
export {};
