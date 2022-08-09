const serializer = require('../lib/serializer')
const signer = require('../lib/signer')

test('compressed JSON cookie value from flask', () => {
  const cookieVal = '.eJwtjrtuAjEQAP_F9RVr7_pxdCAQRRqkRBddhez1LiAhinsIJRH_jotMOZpi_sxZJ5mvZrNMq3TmfKtmYyx5rKFyQEGuwkBJozhpvpImBN-MRNC-pBgTBZ8ThuRdrtmTdVYzgrUs4BCoKDgtFUp1Qr0TXwowcdEWIJMEZfDoAAAbUnownZmXvEhb-R62P3s9-rGfhxOPjwN_Pod7_N19fTxPlxaus0z_1-b1BvjtO9g.YvG-YQ.y71Yawu7ZpBG93sjBtkq1PKKSU0'
  const s = new serializer.Serializer({
    secretKey: 'secret-os-key-local',
    salt: 'cookie-session',
    digestMethod: 'sha1',
    keyDerivation: signer.KeyDerivation.HMAC,
  })
  expect(s.load(cookieVal)).toStrictEqual({
    _fresh: true,
    _id: '1453d6dc63e3cdec048f7e2e145d4f8305048e70f9b8778465a836852ada54121fa3011ce02304bf02fbd0bd2e492e5bb0c4cbf1ce3c4e6fc05320003333eb90',
    state: 'WVAyDfG5Y9sVPcYnEcSwVl7zBTKwPg',
    user_id: '1'
  })
})

test('can verify self serialized cookie value', () => {
  const data = {'foo': 7, 'bar': [1, 2, 3]}
  const s = new serializer.Serializer({
    secretKey: 'secret-key',
    salt: 'salt',
  })
  const cookie = s.dump(data)
  const decodedData = s.load(cookie)
  expect(decodedData).toStrictEqual(data)
})


test('mangled signature fails', () => {
  const data = {'foo': 7, 'bar': [1, 2, 3]}
  const s = new serializer.Serializer({secretKey: 'secret-key', salt: 'salt'})
  let cookie = s.dump(data)
  cookie = cookie.substring(0, cookie.length - 4) + 'aaaa'
  expect(() => { s.load(cookie) }).toThrow(signer.BadSignatureError)
})