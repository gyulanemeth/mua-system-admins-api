import admins from './routes/admins.js'
import login from './routes/login.js'
import invitation from './routes/invitation.js'
import forgotPassword from './routes/forgotPassword.js'

export default ({ apiServer, AdminModel }) => {
  admins({ apiServer, AdminModel })
  login({ apiServer, AdminModel })
  invitation({ apiServer, AdminModel })
  forgotPassword({ apiServer, AdminModel })
}
