import { readOne, createOne, patchOne, list } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'
import allowAccessTo from '../helpers/allowAccessTo.js'
import crypto from 'crypto'
import MethodNotAllowedError from '../errors/MethodNotAllowedError.js'
import NotFoundError from '../errors/NotFoundError.js'
import jwt from 'jsonwebtoken'
export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/invitation/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.params, req.query)
    if (response.result.items.length > 0) {
      throw new NotFoundError(' User exist')
    }
    const newAdmin = await createOne(AdminModel, req.params, req.body)

    const payload = {
      type: 'admin-invitation',
      user: {
        _id: newAdmin.result._id,
        email: newAdmin.result.email
      }
    }
    const token = 'Bearer ' + jwt.sign(payload, secrets[0])
    console.log(token)

    // call mail
    return {
      status: 201,
      result: {
        success: true
      }
    }
  })

  apiServer.post('/v1/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'admin-invitation' }])
    const response = await readOne(AdminModel, { id: data.user._id }, req.query)
    if (response.result.password) {
      throw new MethodNotAllowedError('User already has a password')
    }
    if (response.result._id && req.body.password === req.body.passwordAgain) {
      const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
      const updatedAdmin = await patchOne(AdminModel, { id: data._id }, { password: hash })
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
