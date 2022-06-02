import jwt from 'jsonwebtoken'

import AuthenticationError from '../errors/AuthenticationError.js'
import AuthorizationError from '../errors/AuthorizationError.js'

function validateJwt(req, secrets) {
  const headers = req.headers

  if (!headers.authorization) {
    throw new AuthenticationError('Authorization header is missing.')
  }

  if (!headers.authorization.startsWith('Bearer ')) {
    throw new AuthenticationError('Authorization header should use the \'Bearer\' schema.')
  }

  const token = headers.authorization.substring(7)

  for (let idx = 0; idx < secrets.length; idx += 1) {
    try {
      return jwt.verify(token, secrets[idx])
    } catch (e) {}
  }

  throw new AuthorizationError('Authorization failed.')
}

function checkAccessObject(accessObj, accessTokenData) {
  return Object.keys(accessObj).reduce((hasAccess, key) => {
    if (!accessTokenData[key]) {
      return false
    }

    if (typeof accessObj[key] === 'object') {
      return hasAccess && checkAccessObject(accessObj[key], accessTokenData[key])
    }
    
    return hasAccess && accessObj[key] === accessTokenData[key]
  }, true)
}

export default (req, secrets, accessList) => {
  const accessTokenData = validateJwt(req, secrets)

  const hasAccess = accessList.some(item => checkAccessObject(item, accessTokenData))

  if (!hasAccess) {
    throw new AuthorizationError('Permission denied.')
  }
  return accessTokenData
}

