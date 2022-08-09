"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signer = exports.defaultDigestMethod = exports.KeyDerivation = exports.UnimplementedError = exports.UnknownKeyDerivationError = exports.BadSignatureError = void 0;
const crypto = require("crypto");
const base64_1 = require("./base64");
class BadSignatureError extends Error {
}
exports.BadSignatureError = BadSignatureError;
class UnknownKeyDerivationError extends Error {
}
exports.UnknownKeyDerivationError = UnknownKeyDerivationError;
class UnimplementedError extends Error {
}
exports.UnimplementedError = UnimplementedError;
var KeyDerivation;
(function (KeyDerivation) {
    KeyDerivation["Concat"] = "concat";
    KeyDerivation["DjangoConcat"] = "django-concat";
    KeyDerivation["HMAC"] = "hmac";
    KeyDerivation["None"] = "none";
})(KeyDerivation = exports.KeyDerivation || (exports.KeyDerivation = {}));
const defaultDigestMethod = (data) => {
    const hash = crypto.createHash('sha1');
    hash.update(data);
    return hash.digest();
};
exports.defaultDigestMethod = defaultDigestMethod;
class DefaultSigningAlgorithm {
    sign(key, value) {
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(value);
        return hmac.digest();
    }
    verify(sig, value, key) {
        let sigBytes;
        if (typeof sig === "string") {
            sigBytes = new TextEncoder().encode(sig);
        }
        else {
            sigBytes = sig;
        }
        const newSig = this.sign(key, value);
        return crypto.timingSafeEqual(sigBytes, newSig);
    }
}
class Signer {
    constructor(args) {
        this.secretKey = args.secretKey;
        this.salt = args.salt || 'itsdangerous.Signer';
        this.separator = args.separator || '.';
        this.keyDerivation = args.keyDerivation || KeyDerivation.DjangoConcat;
        this.digestMethod = args.digestMethod || exports.defaultDigestMethod;
        this.signingAlgorithm = args.signingAlgorithm || new DefaultSigningAlgorithm();
    }
    deriveKey(secretKey) {
        secretKey = secretKey || this.secretKey;
        if (this.keyDerivation == KeyDerivation.Concat) {
            return this.digestMethod(this.salt + secretKey);
        }
        else if (this.keyDerivation == KeyDerivation.DjangoConcat) {
            return this.digestMethod(this.salt + 'signer' + secretKey);
        }
        else if (this.keyDerivation == KeyDerivation.HMAC) {
            if (this.digestMethod !== exports.defaultDigestMethod) {
                throw new UnimplementedError("hmac key derivation not unimplemented with non sha1 digest");
            }
            const hmac = crypto.createHmac('sha1', secretKey);
            hmac.update(this.salt);
            return hmac.digest();
        }
        else if (this.keyDerivation == KeyDerivation.None) {
            return new TextEncoder().encode(secretKey);
        }
        else {
            throw new UnknownKeyDerivationError('unknown key derivation: ' + this.keyDerivation);
        }
    }
    sign(msg) {
        const sig = this.signingAlgorithm.sign(this.deriveKey(), msg);
        return msg + this.separator + (0, base64_1.base64encode)(sig);
    }
    unsign(signedMsg) {
        const lastIdx = signedMsg.lastIndexOf(this.separator);
        if (lastIdx < 0) {
            throw new BadSignatureError('missing signature');
        }
        const sigB64 = signedMsg.substring(lastIdx + 1);
        const payload = signedMsg.substring(0, lastIdx);
        const sig = (0, base64_1.base64decode)(sigB64);
        if (!this.signingAlgorithm.verify(sig, payload, this.deriveKey())) {
            throw new BadSignatureError('bad signature');
        }
        return payload;
    }
}
exports.Signer = Signer;
//# sourceMappingURL=signer.js.map