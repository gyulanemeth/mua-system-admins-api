import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import { createOne, patchOne, list, deleteOne } from 'mongoose-crudl'
import { MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AdminModel from '../models/Admin.js'

const secrets = process.env.SECRETS.split(' ')

export default (apiServer) => {
  const sendInvitation = async (email, token) => {
    const url = 'https://api.staging.bluefox.email/v1/accounts/64ca178285926a72bcaba430/projects/65a20f44d75cd7fdb49bb7b9/transactional-emails/65a20f97d75cd7fdb49bb825/send'
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.APP_URL}invitation/accept?token=${token}` }
      })
    })
    return response.json()
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
    return {
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
    return {
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
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
