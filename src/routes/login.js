import { list } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    const findUser = await list(AdminModel, { email: req.body.email }, req.query)
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    if (findUser.result.password === hash) {
      const payload = {
        type: 'admin-login',
        user: {
          _id: findUser.result.items[0]._id,
          email: findUser.result.items[0].email
        }
      }
      const token = jwt.sign(payload, secrets[0])
      return {
        status: 200,
        result: {
          loginToken: 'Bearer ' + token
        }
      }
    }
  })
}
