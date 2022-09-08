import createApiServer from 'express-async-api'

import admins from './admins.js'
import login from './login.js'
import invitation from './invitation.js'
import forgotPassword from './forgotPassword.js'
import config from './config.js'

export default (sendEmail) => {
  function errorHandler (e) {
    return {
      status: e.status,
      error: {
        name: e.name,
        message: e.message
      }
    }
  }

  const apiServer = createApiServer(errorHandler, () => {})

  admins(apiServer)
  login(apiServer)
  invitation(apiServer, sendEmail)
  forgotPassword(apiServer)
  config(apiServer)

  return apiServer
}
