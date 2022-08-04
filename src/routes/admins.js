import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import { list, readOne, deleteOne, patchOne } from 'mongoose-crudl'
import { AuthorizationError, MethodNotAllowedError, ValidationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AdminModel from '../models/Admin.js'
import sendEmail from '../helpers/sendEmail.js'

const secrets = process.env.SECRETS.split(' ')

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const VerifyEmail = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'verifyEmail.html'), 'utf8')

export default (apiServer) => {
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
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.patch('/v1/admins/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    await patchOne(AdminModel, { id: req.params.id }, { name: req.body.name })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/admins/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError('Validation error passwords didn\'t match.')
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const oldHash = crypto.createHash('md5').update(req.body.oldPassword).digest('hex')
    const getAdmin = await readOne(AdminModel, { id: req.params.id }, req.query)
    if (oldHash !== getAdmin.result.password) {
      throw new AuthorizationError('Wrong password.')
    }
    await patchOne(AdminModel, { id: req.params.id }, { password: hash })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.patch('/v1/admins/:id/email', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    const checkExist = await list(AdminModel, { email: req.body.newEmail })
    if (checkExist.result.count > 0) {
      throw new MethodNotAllowedError('Email exist')
    }
    const response = await readOne(AdminModel, { id: req.params.id }, { select: { password: 0, email: 0 } })
    const payload = {
      type: 'verfiy-email',
      user: response.result,
      newEmail: req.body.newEmail
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(VerifyEmail)
    const html = template({ href: `${process.env.APP_URL}verify-email?token=${token}` })
    const mail = await sendEmail(req.body.newEmail, 'verify email link ', html)

    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/admins/:id/email-confirm', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'verfiy-email', user: { _id: req.params.id } }])
    await patchOne(AdminModel, { id: req.params.id }, { email: data.newEmail })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
