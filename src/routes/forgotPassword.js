import { list, readOne, patchOne } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'
import allowAccessTo from '../helpers/allowAccessTo.js'
import NotFoundError from '../errors/NotFoundError.js'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/forgot-password/send', async req => {
    const response = await list(AdminModel, req.params, req.query)
    if (response.result.items.length === 0) {
      throw new NotFoundError(' User does not exist')
    }

    const payload = {
      type: 'forgotPasswordToken',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }
    const token = 'Bearer ' + jwt.sign(payload, secrets[0])
    console.log(token)
    // call mail
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.post('/v1/forgot-password/reset', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'forgotPasswordToken' }])
    const response = await readOne(AdminModel, { id: data.user._id }, req.query)
    if (!response.result._id) {
      throw new NotFoundError('User does not exist')
    }
    if (response.result._id && req.body.password === req.body.passwordAgain) {
      const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
      const updatedAdmin = await patchOne(AdminModel, { id: data.user._id }, { password: hash })
      const payload = {
        type: 'admin-login',
        user: {
          _id: updatedAdmin.result._id,
          email: updatedAdmin.result.email
        }
      }
      const token = 'Bearer ' + jwt.sign(payload, secrets[0])
      return {
        status: 200,
        result: {
          loginToken: token
        }
      }
    }
  })
}
