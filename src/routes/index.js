import createApiServer from 'express-async-api'

import admins from './admins.js'
import login from './login.js'
import invitation from './invitation.js'
import forgotPassword from './forgotPassword.js'
import config from './config.js'

export default (sendEmail, maxFileSize) => {
  function errorHandler (e) {
    if (e.code === 'LIMIT_FILE_SIZE') {
      return {
        status: 413,
        error: {
          name: 'PAYLOAD_TOO_LARGE',
          message: 'File size limit exceeded. Maximum file size allowed is ' + maxFileSize
        }
      }
    }
    return {
      status: e.status,
      error: {
        name: e.name,
        message: e.message
      }
    }
  }

  const apiServer = createApiServer(errorHandler, () => {})

  admins(apiServer, maxFileSize)
  login(apiServer)
  invitation(apiServer, sendEmail)
  forgotPassword(apiServer)
  config(apiServer)

  return apiServer
}
