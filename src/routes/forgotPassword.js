import { list, patchOne } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'
import Email from '../helpers/Email.js'
import handlebars from 'handlebars'
import allowAccessTo from 'bearer-jwt-auth'
import { AuthenticationError, ValidationError } from 'standard-api-errors'
import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const forgetPassword = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'forgot-password.html'), 'utf8')

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/forgot-password/send', async req => {
    const response = await list(AdminModel, req.body, req.query)
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
    const token = jwt.sign(payload, secrets[0])
    const template = handlebars.compile(forgetPassword)
    const html = template({ token })
    Email('example@example.com', 'forget password link', html)
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })

  apiServer.post('/v1/forgot-password/reset', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'forgot-password' }])
    if (req.body.password !== req.body.passwordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const response = await list(AdminModel, { id: data.user._id, email: data.user.email }, req.query)
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    const updatedAdmin = await patchOne(AdminModel, { id: data.user._id }, { password: hash })
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
