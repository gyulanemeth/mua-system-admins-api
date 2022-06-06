import { readOne, createOne, patchOne, list } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'
import Email from '../models/Email.js'
import allowAccessTo from '../helpers/allowAccessTo.js'
import crypto from 'crypto'
import MethodNotAllowedError from '../errors/MethodNotAllowedError.js'
import ValidationError from '../errors/ValidationError.js'
import NotFoundError from '../errors/NotFoundError.js'
import jwt from 'jsonwebtoken'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/invitation/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.body, req.query)
    if (response.result.count !== 0) {
      throw new MethodNotAllowedError('User exist')
    }
    const newAdmin = await createOne(AdminModel, req.body, req.query)

    const payload = {
      type: 'invitation',
      user: {
        _id: newAdmin.result._id,
        email: newAdmin.result.email
      }
    }
    const token = 'Bearer ' + jwt.sign(payload, secrets[0])

    Email("example@example.com", "invitation link ", `<h1>here is ur token: ${token}</h1>`)


    return {
      status: 201,
      result: {
        success: true
      }
    }
  })

  apiServer.post('/v1/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation' }])
    const response = await readOne(AdminModel, { id: data.user.id}, req.query)
    if (response.result.password) {
      throw new MethodNotAllowedError('User already has a password')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }

      const hash = crypto.createHash('md5').update(req.body.newPasswordAgain).digest('hex')
      const updatedAdmin = await patchOne(AdminModel, { id: data.user.id }, { password: hash })
      const payload = {
        type: 'login',
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
  })
}
