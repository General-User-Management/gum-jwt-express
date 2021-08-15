const jwt = require('jsonwebtoken')
const UnauthorizedError = require('./errors/UnauthorizedError')
const unless = require('express-unless')
const async = require('async')
const set = require('lodash.set')
const axios = require('axios')

const DEFAULT_REVOKED_FUNCTION = function (_, __, cb) { return cb(null, false) }

function isFunction (object) {
  return Object.prototype.toString.call(object) === '[object Function]'
}

function wrapStaticSecretInCallback (secret) {
  return function (_, __, cb) {
    return cb(null, secret)
  }
}

function _getSecretFromAuthServer (serverUrl) {
  return new Promise((resolve, reject) => {
    axios.get(serverUrl)
      .then(res => {
        process.env.JWT_SECRET = res.data.data
        resolve(res.data.data)
      }).catch(err => {
        reject(err)
      })
  })
}

function getSecret (serverUrl) {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET
  return _getSecretFromAuthServer(serverUrl)
}

module.exports = async function (options) {
  if (!options || !options.secret) {
    // 如果有设置secret，则不获取token;否则从authServer拉取token
    if (options.authServerUrl) {
      options.secret = await getSecret(options.authServerUrl)
    } else {
      throw new Error('secret or authServer should be set')
    }
  }

  let secretCallback = options.secret

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback)
  }

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION

  const _requestProperty = options.userProperty || options.requestProperty || 'user'
  const _resultProperty = options.resultProperty
  const credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired

  const middleware = function (req, res, next) {
    let token

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) { // eslint-disable-line
      const hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
        .split(',').map(function (header) {
          return header.trim()
        }).indexOf('authorization')

      if (hasAuthInAccessControl) {
        return next()
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req)
      } catch (e) {
        return next(e)
      }
    } else if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        const credentials = parts[1]

        if (/^Bearer$/i.test(scheme)) {
          token = credentials
        } else {
          if (credentialsRequired) {
            return next(new UnauthorizedError('credentials_bad_scheme', { message: 'Format is Authorization: Bearer [token]' }))
          } else {
            return next()
          }
        }
      } else {
        return next(new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' }))
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new UnauthorizedError('credentials_required', { message: 'No authorization token was found' }))
      } else {
        return next()
      }
    }

    let dtoken

    try {
      dtoken = jwt.decode(token, { complete: true }) || {}
    } catch (err) {
      return next(new UnauthorizedError('invalid_token', err))
    }

    async.waterfall([
      function getSecret (callback) {
        const arity = secretCallback.length
        if (arity === 4) {
          secretCallback(req, dtoken.header, dtoken.payload, callback)
        } else { // arity == 3
          secretCallback(req, dtoken.payload, callback)
        }
      },
      function verifyToken (secret, callback) {
        jwt.verify(token, secret, options, function (err, decoded) {
          if (err) {
            callback(new UnauthorizedError('invalid_token', err))
          } else {
            callback(null, decoded)
          }
        })
      },
      function checkRevoked (decoded, callback) {
        isRevokedCallback(req, dtoken.payload, function (err, revoked) {
          if (err) {
            callback(err)
          } else if (revoked) {
            callback(new UnauthorizedError('revoked_token', { message: 'The token has been revoked.' }))
          } else {
            callback(null, decoded)
          }
        })
      }

    ], function (err, result) {
      if (err) { return next(err) }
      if (_resultProperty) {
        set(res, _resultProperty, result)
      } else {
        set(req, _requestProperty, result)
      }
      next()
    })
  }

  middleware.unless = unless
  middleware.UnauthorizedError = UnauthorizedError

  return middleware
}

module.exports.UnauthorizedError = UnauthorizedError
