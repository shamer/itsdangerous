const serializer = require('./serializer')
const signer = require('./signer')

test('compressed JSON cookie value from flask', () => {
  const cookieVal = '.eJwlzrtuQjEMANB_ycwQO7mJzVZVHfgEJmQ7tqhKH7qhtFXFv4PEfobznw6x-jymbchp-iYdXkfaJmOMogMyqNOoygyEOmQhLu6tWFcNVFYLquLWKtMSkRdoGUcx4F69wMAuXK1jeO5B3asqGpEgSwYBauHNnHsGj5ZHWCEVR0mbNM9y9nsFXp72X3H5aO_w7G-_3S4rlr_dbv587k_lDr-nr491S9cbDTg-BA.YvGxeg.HI6IzQTGGl99J0TYb9n7soLRiz4'
  const s = new serializer.Serializer({secretKey: 'secret-key', salt: 'salt'})
  s.load(cookieVal)
})

test('can verify self serialized cookie value', () => {
  const data = {'foo': 7, 'bar': [1, 2, 3]}
  const s = new serializer.Serializer({secretKey: 'secret-key', salt: 'salt'})
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