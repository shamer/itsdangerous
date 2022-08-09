
const fromUrlSafe = (data: string): string => {
  // URL safe base64 swapps the following characters
  // '+' with '-'
  // '/' with '_'
  // padding is removed
  const padding = (-data.length % 4) + 4
  if (padding) {
    data += '='.repeat(padding)
  }
  return data
    .replace(/-/g, '+')
    .replace(/_/g, '/')
}

const toUrlSafe = (data: string): string => {
  return data
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

}

export const base64decode = (data: string): Uint8Array => {
  return Buffer.from(fromUrlSafe(data), 'base64')
}

export const base64encode = (data: NodeJS.ArrayBufferView): string => {
  const buff = Buffer.from(data.buffer)
  return toUrlSafe(buff.toString('base64'))
}