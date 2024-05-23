import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import { list, patchOne } from 'mongoose-crudl'
import { AuthenticationError, ValidationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

const secrets = process.env.SECRETS.split(' ')
const forgotPasswordTemplate = process.env.ADMIN_BLUEFOX_FORGOT_PASSWORD_TEMPLATE

export default ({
  apiServer, AdminModel,
  hooks =
  {
    forgotPasswordSend: { post: (params) => { } },
    forgotPasswordReset: { post: (params) => { } }
  }
}) => {
  const sendForgotPassword = async (email, token) => {
    const url = forgotPasswordTemplate
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.APP_URL}forgot-password/reset?token=${token}` }
      })
    })
    const res = await response.json()
    if (res.status !== 200) {
      throw res
    }
    return res
  }

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
    const mail = await sendForgotPassword(response.result.items[0].email, token)
    let postRes
    if (hooks.forgotPasswordSend?.post) {
      postRes = await hooks.forgotPasswordSend.post(req.params, req.body, mail)
    }
    return postRes || {
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
    let postRes
    if (hooks.forgotPasswordReset?.post) {
      postRes = await hooks.forgotPasswordReset.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
