import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import { createOne, patchOne, list, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AdminModel from '../models/Admin.js'

const secrets = process.env.SECRETS.split(' ')

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const Invitation = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'invitation.html'), 'utf8')

export default (apiServer, sendEmail) => {
  apiServer.post('/v1/invitation/send', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.body, { select: { password: 0 } })
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
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(Invitation)
    const html = template({ href: `${process.env.APP_URL}invitation/accept?token=${token}` })
    let mail
    try {
      mail = await sendEmail({ to: newAdmin.result.email, subject: 'invitation link ', html })
    } catch (e) {
      await deleteOne(AdminModel, { id: newAdmin.result._id })
      throw e
    }
    return {
      status: 201,
      result: {
        success: true,
        info: { mail: mail.result.info, admin: newAdmin.result }
      }
    }
  })

  apiServer.post('/v1/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation' }])
    const response = await list(AdminModel, { id: data.user._id, email: data.user.email }, req.query)
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    if (response.result.items[0].password) {
      throw new MethodNotAllowedError('User already has a password')
    }
    if (req.body.newPassword !== req.body.newPasswordAgain) { // check password matching
      throw new ValidationError("Validation error passwords didn't match ")
    }

    const hash = crypto.createHash('md5').update(req.body.newPasswordAgain).digest('hex')
    const updatedAdmin = await patchOne(AdminModel, { id: data.user._id }, { password: hash, name: req.body.name })
    const payload = {
      type: 'login',
      user: {
        _id: updatedAdmin.result._id,
        email: updatedAdmin.result.email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
