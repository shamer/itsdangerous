"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Serializer = void 0;
const zlib = require("zlib");
const signer_1 = require("./signer");
const base64_1 = require("./base64");
const defaultSerializer = { dump: JSON.stringify, parse: JSON.parse };
const defaultSigner = signer_1.Signer;
class Serializer {
    constructor(args) {
        this.secretKey = args.secretKey;
        this.salt = args.salt || "itsdangerous";
        this.separator = args.separator || '.';
        this.serializer = args.serializer || defaultSerializer;
        this.signer = new defaultSigner({
            secretKey: this.secretKey,
            salt: this.salt,
            separator: this.separator,
            keyDerivation: args.keyDerivation,
        });
    }
    dump(obj) {
        const payloadStr = this.serializer.dump(obj);
        const payloadB64 = (0, base64_1.base64encode)(new TextEncoder().encode(payloadStr));
        return this.signer.sign(payloadB64);
    }
    load(data) {
        if (data.length === 0) {
            throw new signer_1.BadSignatureError('cannot load from empty value');
        }
        let payload = this.unsign(data);
        return this.serializer.parse(payload.toString());
    }
    unsign(data) {
        const signedMsg = this.signer.unsign(data);
        const signedAtSepIdx = signedMsg.lastIndexOf(this.separator);
        let payload;
        if (signedAtSepIdx >= 0) {
            const signedAtB64 = signedMsg.substring(signedAtSepIdx + 1);
            payload = signedMsg.substring(0, signedAtSepIdx);
        }
        else {
            payload = signedMsg;
        }
        const isCompressed = payload[0] === this.separator;
        if (isCompressed) {
            payload = zlib.unzipSync((0, base64_1.base64decode)(payload.substring(1)));
        }
        else {
            payload = (0, base64_1.base64decode)(payload);
        }
        return payload;
    }
}
exports.Serializer = Serializer;
//# sourceMappingURL=serializer.js.map