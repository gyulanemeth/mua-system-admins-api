import jwt from 'jsonwebtoken'

import AuthenticationError from '../errors/AuthenticationError.js'
import AuthorizationError from '../errors/AuthorizationError.js'

// we are going to create a small generic lib from this function, because it can be used in all of the upcoming backends


function validateJwt(req, secrets) {
  const headers = req.headers

  if (!headers.authorization) {
    throw new BackendError('AUTHENTICATION_ERROR', 'Authorization header is missing.')
  }

  if (!headers.authorization.startsWith('Bearer ')) {
    throw new BackendError('AUTHENTICATION_ERROR', 'Authorization header should use the \'Bearer\' schema.')
  }

  const token = headers.authorization.substring(7)

  for (let idx = 0; idx < secrets.length; idx += 1) {
    try {
      return jwt.verify(token, secrets[idx])
    } catch (e) {}
  }

  throw new BackendError('AUTHORIZATION_ERROR', 'Authorization failed.')
}

/*
accessList: array of objects
 - type: admin / backend / user
 - accountId

 usage:
 allowAccessTo(req, [
   { type: 'backend' },
   { type: 'admin' },
   { type: 'user', accountId: 'xxx333xxasdf' }
 ])
*/

export default (req, secrets, accessList) => {
  // check if bearer token -> if not 401 (on req.headers.authorization)
  // check if the token can be decoded with a secret -> if not 403
  // check if the token's body satisfies at least one of the things in the accessList

  const accessTokenData = validateJwt(req, secrets)

  const hasAccess = accessList.some(item => {
    return Object.keys(item).reduce((hasAccess, key) => {
      return hasAccess && item[key] === accessTokenData[key]
    }, true)
  })

  if (!hasAccess) {
    throw new BackendError('AUTHORIZATION_ERROR', 'Permission denied.')
  }
  return accessTokenData
}

