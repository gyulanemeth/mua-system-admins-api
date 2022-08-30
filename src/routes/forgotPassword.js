import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import { list, patchOne } from 'mongoose-crudl'
import { AuthenticationError, ValidationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AdminModel from '../models/Admin.js'
import sendEmail from 'aws-ses-send-email'

const secrets = process.env.SECRETS.split(' ')

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const forgetPassword = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'forgot-password.html'), 'utf8')

export default (apiServer) => {
  apiServer.post('/v1/forgot-password/send', async req => {
    const response = await list(AdminModel, req.body, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    const payload = {
      type: 'forgot-password',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(forgetPassword)
    const html = template({ href: `${process.env.APP_URL}forgot-password/reset?token=${token}` })
    const mail = await sendEmail({ to: response.result.items[0].email, subject: 'forget password link', html })
    return {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.post('/v1/forgot-password/reset', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'forgot-password' }])
    if (req.body.newPassword !== req.body.newPasswordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.newPassword).digest('hex')
    const updatedAdmin = await patchOne(AdminModel, { id: data.user._id, email: data.user.email }, { password: hash })
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
