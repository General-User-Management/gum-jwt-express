const jwt = require('jsonwebtoken')
const assert = require('assert')

const expressjwt = require('../lib')
const UnauthorizedError = require('../lib/errors/UnauthorizedError')

describe('revoked jwts', function () {
  const secret = 'shhhhhh'

  const revoked_id = '1234'

  const middleware = expressjwt({
    secret: secret,
    isRevoked: function (req, payload, done) {
      done(null, payload.jti && payload.jti === revoked_id)
    }
  })

  it('should throw if token is revoked', function () {
    const req = {}
    const res = {}
    const token = jwt.sign({ jti: revoked_id, foo: 'bar' }, secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    middleware(req, res, function (err) {
      assert.ok(err)
      assert.equal(err.code, 'revoked_token')
      assert.equal(err.message, 'The token has been revoked.')
    })
  })

  it('should work if token is not revoked', function () {
    const req = {}
    const res = {}
    const token = jwt.sign({ jti: '1233', foo: 'bar' }, secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    middleware(req, res, function () {
      assert.equal('bar', req.user.foo)
    })
  })

  it('should throw if error occurs checking if token is revoked', function () {
    const req = {}
    const res = {}
    const token = jwt.sign({ jti: revoked_id, foo: 'bar' }, secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    expressjwt({
      secret: secret,
      isRevoked: function (req, payload, done) {
        done(new Error('An error ocurred'))
      }
    })(req, res, function (err) {
      assert.ok(err)
      assert.equal(err.message, 'An error ocurred')
    })
  })
})
