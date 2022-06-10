import { list, readOne, deleteOne, patchOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import AdminModel from '../models/Admin.js'
import { MethodNotAllowedError, ValidationError } from 'standard-api-errors'

import allowAccessTo from 'bearer-jwt-auth'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.get('/v1/admins/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.params, req.query)
    response.result.items = response.result.items.map(user => {
      user.invitationAccepted = !!user.password
      delete user.password
      return user
    })

    return response
  })

  apiServer.get('/v1/admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await readOne(AdminModel, { id: req.params.id }, req.query)
    return response
  })

  apiServer.delete('/v1/admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const adminCount = await AdminModel.count({})

    if (adminCount === 1) {
      throw new MethodNotAllowedError('Removeing the last admin is not allowed')
    }
    const response = await deleteOne(AdminModel, { id: req.params.id })

    return response
  })

  apiServer.get('/v1/admins/:id/access-token', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }, { type: 'login', user: { _id: req.params.id } }])

    const response = await readOne(AdminModel, { id: req.params.id }, { select: { password: 0 } })
    const payload = {
      type: 'admin',
      user: {
        _id: response.result._id,
        email: response.result.email
      }
    }
    const token = jwt.sign(payload, secrets[0])
    return {
      status: 200,
      result: {
        accessToken: 'Bearer ' + token
      }
    }
  })

  apiServer.patch('/v1/admins/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])

    await patchOne(AdminModel, { id: req.params.id }, req.body)

    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/admins/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }]) // check auth
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex') // hash the new password
    await patchOne(AdminModel, { id: req.params.id }, { password: hash }) // update user password
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
