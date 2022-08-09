import * as zlib from 'zlib'
import { Signer, BadSignatureError, KeyDerivation } from './signer'
import { base64decode, base64encode } from './base64'

const defaultSerializer = {dump: JSON.stringify, parse: JSON.parse}
const defaultSigner = Signer

export class Serializer {
  secretKey: string
  salt: string
  serializer: {dump: (data: Object) => string, parse: (msg: string) => Object}
  separator: string
  signer: Signer

  constructor(args: {
    secretKey: string,
    salt?: string,
    serializer?: {dump: (data: Object) => string, parse: (msg: string) => Object}
    separator?: string,
    keyDerivation?: KeyDerivation,
  }) {
    this.secretKey = args.secretKey
    this.salt = args.salt || "itsdangerous"
    this.separator = args.separator || '.'

    this.serializer = args.serializer || defaultSerializer
    this.signer = new defaultSigner({
      secretKey: this.secretKey,
      salt: this.salt,
      separator: this.separator,
      keyDerivation: args.keyDerivation,
    })
  }

  dump(obj: Object) {
    const payloadStr = this.serializer.dump(obj)
    const payloadB64 = base64encode(new TextEncoder().encode(payloadStr))
    return this.signer.sign(payloadB64)
  }

  load(data: string): Object {
    if (data.length === 0) {
      throw new BadSignatureError('cannot load from empty value')
    }
    let payload = this.unsign(data)
    return this.serializer.parse(payload.toString())
  }

  unsign(data: string): Uint8Array {
    const signedMsg = this.signer.unsign(data)
    const signedAtSepIdx = signedMsg.lastIndexOf(this.separator)
    let payload
    if (signedAtSepIdx >= 0) {
      const signedAtB64 = signedMsg.substring(signedAtSepIdx + 1)
      payload = signedMsg.substring(0, signedAtSepIdx)
      // TODO include "valid for" logic
    } else {
      payload = signedMsg
    }

    const isCompressed = payload[0] === this.separator
    if (isCompressed) {
      payload = zlib.unzipSync(base64decode(payload.substring(1)))
    } else {
      payload = base64decode(payload)
    }
    return payload
  }
}
