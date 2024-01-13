import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import mime from 'mime-types'

import { list, readOne, deleteOne, patchOne } from 'mongoose-crudl'
import { AuthorizationError, MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import AdminModel from '../models/Admin.js'
import aws from '../helpers/awsBucket.js'

const secrets = process.env.SECRETS.split(' ')
const bucketName = process.env.AWS_BUCKET_NAME
const folderName = process.env.AWS_FOLDER_NAME

const s3 = await aws()

export default (apiServer, maxFileSize) => {
  const sendVerifyEmail = async (email, token) => {
    const url = 'https://api.staging.bluefox.email/v1/accounts/64ca178285926a72bcaba430/projects/65a20f44d75cd7fdb49bb7b9/transactional-emails/65a20fe1d75cd7fdb49bb83d/send'
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.APP_URL}verify-email?token=${token}` }
      })
    })
    return response.json()
  }

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
    const response = await readOne(AdminModel, { id: req.params.id }, { ...req.query, select: { password: 0 } })
    return response
  })

  apiServer.delete('/v1/admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    const adminCount = await AdminModel.count({})
    if (adminCount === 1) {
      throw new MethodNotAllowedError('Removing the last admin is not allowed')
    }
    const response = await deleteOne(AdminModel, { id: req.params.id }, { password: 0 })
    return response
  })

  apiServer.post('/v1/admins/permission/:permissionFor', async req => {
    const tokenData = allowAccessTo(req, secrets, [{ type: 'admin' }])
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(AdminModel, { email: tokenData.user.email, password: hash })
    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid password')
    }
    const payload = {
      type: req.params.permissionFor,
      user: tokenData.user
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '5m' })
    return {
      status: 200,
      result: {
        permissionToken: token
      }
    }
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
    if (req.body.newEmail !== req.body.newEmailAgain) {
      throw new ValidationError('Validation error email didn\'t match.')
    }
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
    const mail = await sendVerifyEmail(req.body.newEmail, token)
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

  apiServer.postBinary('/v1/admins/:id/profile-picture', { mimeTypes: ['image/jpeg', 'image/png', 'image/gif'], fieldName: 'profilePicture', maxFileSize }, async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])

    const uploadParams = {
      Bucket: bucketName,
      Body: req.file.buffer,
      Key: `${folderName}/${req.params.id}.${mime.extension(req.file.mimetype)}`
    }

    const result = await s3.upload(uploadParams).promise()
    await patchOne(AdminModel, { id: req.params.id }, { profilePicture: process.env.CDN_BASE_URL + result.Key })
    return {
      status: 200,
      result: {
        profilePicture: process.env.CDN_BASE_URL + result.Key
      }
    }
  })

  apiServer.delete('/v1/admins/:id/profile-picture', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    const userData = await readOne(AdminModel, { id: req.params.id }, { select: { password: 0, email: 0 } })
    const key = userData.result.profilePicture.substring(userData.result.profilePicture.lastIndexOf('/') + 1)

    await s3.deleteObject({
      Bucket: bucketName,
      Key: `${folderName}/${key}`
    }).promise()
    await patchOne(AdminModel, { id: req.params.id }, { profilePicture: null })
    return {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
