import * as zlib from 'zlib'
import { Signer, BadSignatureError } from './signer'
import { base64decode, base64encode } from './base64'

const defaultSerializer = {dump: JSON.stringify, parse: JSON.parse}
const defaultSigner = Signer

export class Serializer {
  secretKey: string
  salt: string
  serializer: {dump: (data: Object) => string, parse: (msg: string) => Object}
  signer: Signer

  constructor(args: {
    secretKey: string,
    salt?: string,
    serializer?: {dump: (data: Object) => string, parse: (msg: string) => Object}
  }) {
    this.secretKey = args.secretKey
    this.salt = args.salt || "itsdangerous"

    this.serializer = args.serializer || defaultSerializer
    this.signer = new defaultSigner({
      secretKey: this.secretKey,
      salt: this.salt,
      separator: '.'
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

    const isCompressed = data[0] === '.'
    if (isCompressed) {
      data = data.substring(1)
    }
    const rawPayload = this.unsign(data)
    const payload = isCompressed ? zlib.unzipSync(rawPayload) : rawPayload
    return this.serializer.parse(payload.toString())
  }

  unsign(data: string): Uint8Array {
    const signedMsg = this.signer.unsign(data)
    const signedAtSepIdx = signedMsg.indexOf('.')
    let payload
    if (signedAtSepIdx >= 0) {
      const signedAtB64 = signedMsg.substring(signedAtSepIdx + 1)
      payload = signedMsg.substring(0, signedAtSepIdx)
      // TODO include "valid for" logic
    } else {
      payload = signedMsg
    }
    return base64decode(payload)
  }
}
