import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import { createOne, patchOne, list, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

const secrets = process.env.SECRETS.split(' ')
const invitationTemplate = process.env.ADMIN_BLUEFOX_INVITATION_TEMPLATE

export default ({
  apiServer, AdminModel,
  hooks =
  {
    invitationSend: { post: (params) => { } },
    invitationResend: { post: (params) => { } },
    invitationAccept: { post: (params) => { } }

  }
}) => {
  const sendInvitation = async (email, token) => {
    const url = invitationTemplate
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.ADMIN_APP_URL}invitation/accept?token=${token}` }
      })
    })
    const res = await response.json()
    if (res.status !== 200) {
      const error = new Error(res.error.message)
      error.status = res.status
      error.name = res.error.name
      throw error
    }
    return res
  }

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
    let mail
    try {
      mail = await sendInvitation(newAdmin.result.email, token)
    } catch (e) {
      await deleteOne(AdminModel, { id: newAdmin.result._id })
      throw e
    }
    let postRes
    if (hooks.invitationSend?.post) {
      postRes = await hooks.invitationSend.post(req.params, req.body, mail)
    }
    return postRes || {
      status: 201,
      result: {
        success: true,
        info: { mail: mail.result.info, admin: newAdmin.result }
      }
    }
  })

  apiServer.post('/v1/invitation/resend', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.body, { select: { password: 0 } })
    if (response.result.count === 0) {
      throw new MethodNotAllowedError("User dosen't exist")
    }
    if (response.result.items[0].name) {
      throw new MethodNotAllowedError('User already verified')
    }
    const payload = {
      type: 'invitation',
      user: {
        _id: response.result.items[0]._id,
        email: response.result.items[0].email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const mail = await sendInvitation(response.result.items[0].email, token)
    let postRes
    if (hooks.invitationResend?.post) {
      postRes = await hooks.invitationResend.post(req.params, req.body, mail)
    }
    return postRes || {
      status: 201,
      result: {
        success: true,
        info: { mail: mail.result.info, admin: response.result.items[0] }
      }
    }
  })

  apiServer.post('/v1/invitation/accept', async req => {
    const data = allowAccessTo(req, secrets, [{ type: 'invitation' }])
    const response = await list(AdminModel, { id: data.user._id, email: data.user.email }, req.query)
    if (response.result.count === 0) {
      throw new AuthenticationError('Check user name')
    }
    if (response.result.items[0].password) { // check if user accepted the invitation before and completed the necessary data.
      throw new MethodNotAllowedError('Token already used, user exists')
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
    let postRes
    if (hooks.invitationAccept?.post) {
      postRes = await hooks.invitationAccept.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
