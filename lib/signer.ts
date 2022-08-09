import * as crypto from 'crypto'

import { base64decode, base64encode } from './base64'

export class BadSignatureError extends Error {}
export class UnknownKeyDerivationError extends Error {}
export class UnimplementedError extends Error {}

type BinaryLike = string|NodeJS.ArrayBufferView

type DigestMethod = (data: BinaryLike) => NodeJS.ArrayBufferView
interface SigningAlgorithm {
  sign(key: BinaryLike, value: BinaryLike): NodeJS.ArrayBufferView
  verify(sig: BinaryLike, value: BinaryLike, key: BinaryLike): boolean
}

export enum KeyDerivation {
  Concat = 'concat',
  DjangoConcat = 'django-concat',
  HMAC = 'hmac',
  None = 'none',
}

const deriveKey = (derivation: KeyDerivation, salt: string, secretKey: string): string => {
  return secretKey
}

const defaultDigestMethod = (data: BinaryLike): NodeJS.ArrayBufferView => {
  const hash = crypto.createHash('sha1')
  hash.update(data)
  return hash.digest()
}

class DefaultSigningAlgorithm {
  sign(key: BinaryLike, value: BinaryLike): NodeJS.ArrayBufferView {
    const hmac = crypto.createHmac('sha1', key)
    hmac.update(value)
    return hmac.digest()
  }
  verify(sig: BinaryLike, value: BinaryLike, key: BinaryLike): boolean {
    let sigBytes: NodeJS.ArrayBufferView
    if (typeof sig === "string") {
      sigBytes = new TextEncoder().encode(sig)
    } else {
      sigBytes = sig
    }
    const newSig = this.sign(key, value)
    return crypto.timingSafeEqual(sigBytes, newSig)
  }
}

export class Signer {
  salt: string
  secretKey: string
  separator: string
  keyDerivation: KeyDerivation
  digestMethod: DigestMethod
  signingAlgorithm: SigningAlgorithm

  constructor(args: {
    secretKey: string,
    salt?: string,
    separator?: string,
    digestMethod?: DigestMethod,
    keyDerivation?: KeyDerivation,
    signingAlgorithm?: SigningAlgorithm,
  }) {
    this.secretKey = args.secretKey
    this.salt = args.salt || 'itsdangerous.Signer'

    // TODO check if the separator is in the base64 alphabet
    this.separator = args.separator || '.'

    this.keyDerivation = args.keyDerivation || KeyDerivation.DjangoConcat
    this.digestMethod = args.digestMethod || defaultDigestMethod
    this.signingAlgorithm = args.signingAlgorithm || new DefaultSigningAlgorithm()
  }

  deriveKey(secretKey?: string): NodeJS.ArrayBufferView {
    secretKey = secretKey || this.secretKey
    if (this.keyDerivation == KeyDerivation.Concat) {
      return this.digestMethod(this.salt + secretKey)
    } else if (this.keyDerivation == KeyDerivation.DjangoConcat) {
      return this.digestMethod(this.salt + 'signer' + secretKey)
    } else if (this.keyDerivation == KeyDerivation.HMAC) {
      throw new UnimplementedError('HMAC key direvation not implemented')
    } else if (this.keyDerivation == KeyDerivation.None) {
      return new TextEncoder().encode(secretKey)
    } else {
      throw new UnknownKeyDerivationError('unknown key derivation: ' + this.keyDerivation)
    }
  }

  /**
   * Sign a message using the key + digest and return the message with attached
   * signature.
   */
  sign(msg: string): string {
    const sig = this.signingAlgorithm.sign(this.deriveKey(), msg)
    return msg + this.separator + base64encode(sig)
  }

  /**
   * Validate the signature of a message. Returns the message if valid. Throws
   * BadSignatureError if invalid.
   */
  unsign(signedMsg: string): string {
    const lastIdx = signedMsg.lastIndexOf(this.separator)
    if (lastIdx < 0) {
      throw new BadSignatureError('missing signature')
    }
    const sigB64 = signedMsg.substring(lastIdx+1)
    const payload = signedMsg.substring(0, lastIdx)
    const sig = base64decode(sigB64)
    if (!this.signingAlgorithm.verify(sig, payload, this.deriveKey())) {
      throw new BadSignatureError('bad signature')
    }
    return payload
  }
}