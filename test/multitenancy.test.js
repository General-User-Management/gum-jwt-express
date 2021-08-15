const jwt = require('jsonwebtoken')
const assert = require('assert')

const expressjwt = require('../lib')
const UnauthorizedError = require('../lib/errors/UnauthorizedError')

describe('multitenancy', function () {
  const req = {}
  const res = {}

  const tenants = {
    a: {
      secret: 'secret-a'
    }
  }

  const secretCallback = function (req, payload, cb) {
    const issuer = payload.iss
    if (tenants[issuer]) {
      return cb(null, tenants[issuer].secret)
    }

    return cb(new UnauthorizedError('missing_secret',
      { message: 'Could not find secret for issuer.' }))
  }

  const middleware = expressjwt({
    secret: secretCallback
  })

  it('should retrieve secret using callback', function () {
    const token = jwt.sign({ iss: 'a', foo: 'bar' }, tenants.a.secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    middleware(req, res, function () {
      assert.equal('bar', req.user.foo)
    })
  })

  it('should throw if an error ocurred when retrieving the token', function () {
    const secret = 'shhhhhh'
    const token = jwt.sign({ iss: 'inexistent', foo: 'bar' }, secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    middleware(req, res, function (err) {
      assert.ok(err)
      assert.equal(err.code, 'missing_secret')
      assert.equal(err.message, 'Could not find secret for issuer.')
    })
  })

  it('should fail if token is revoked', function () {
    const token = jwt.sign({ iss: 'a', foo: 'bar' }, tenants.a.secret)

    req.headers = {}
    req.headers.authorization = 'Bearer ' + token

    const middleware = expressjwt({
      secret: secretCallback,
      isRevoked: function (req, payload, done) {
        done(null, true)
      }
    })(req, res, function (err) {
      assert.ok(err)
      assert.equal(err.code, 'revoked_token')
      assert.equal(err.message, 'The token has been revoked.')
    })
  })
})
