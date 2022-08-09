import { Signer, KeyDerivation } from './signer';
export declare class Serializer {
    secretKey: string;
    salt: string;
    serializer: {
        dump: (data: Object) => string;
        parse: (msg: string) => Object;
    };
    separator: string;
    signer: Signer;
    constructor(args: {
        secretKey: string;
        salt?: string;
        serializer?: {
            dump: (data: Object) => string;
            parse: (msg: string) => Object;
        };
        separator?: string;
        keyDerivation?: KeyDerivation;
    });
    dump(obj: Object): string;
    load(data: string): Object;
    unsign(data: string): Uint8Array;
}
