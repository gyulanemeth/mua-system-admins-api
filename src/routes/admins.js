import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import mime from 'mime-types'

import { list, readOne, deleteOne, patchOne } from 'mongoose-crudl'
import { AuthorizationError, MethodNotAllowedError, ValidationError, AuthenticationError } from 'standard-api-errors'
import allowAccessTo from 'bearer-jwt-auth'

import aws from '../helpers/awsBucket.js'

const secrets = process.env.SECRETS.split(' ')
const bucketName = process.env.AWS_BUCKET_NAME
const folderName = process.env.AWS_FOLDER_NAME
const verifyEmailTemplate = process.env.ADMIN_BLUEFOX_VERIFY_EMAIL_TEMPLATE
const maxFileSize = process.env.MAX_FILE_SIZE

const s3 = await aws()

export default ({
  apiServer, AdminModel,
  hooks =
  {
    listAdmins: { post: (params) => { } },
    readOneAdmin: { post: (params) => { } },
    deleteAdmin: { post: (params) => { } },
    permissionFor: { post: (params) => { } },
    accessToken: { post: (params) => { } },
    updateName: { post: (params) => { } },
    updatePassword: { post: (params) => { } },
    updateEmail: { post: (params) => { } },
    confirmEmail: { post: (params) => { } },
    addProfilePicture: { post: (params) => { } },
    deleteProfilePicture: { post: (params) => { } }
  }
}) => {
  const sendVerifyEmail = async (email, token) => {
    const url = verifyEmailTemplate
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + process.env.ADMIN_BLUEFOX_API_KEY
      },
      body: JSON.stringify({
        email,
        data: { href: `${process.env.ADMIN_APP_URL}verify-email?token=${token}` }
      })
    })
    const res = await response.json()
    if (res.status !== 200) {
      throw res
    }
    return res
  }

  apiServer.get('/v1/admins/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AdminModel, req.params, req.query)
    response.result.items = response.result.items.map(user => {
      user.invitationAccepted = !!user.password
      delete user.password
      return user
    })
    let postRes
    if (hooks.listAdmins?.post) {
      postRes = await hooks.listAdmins.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.get('/v1/admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await readOne(AdminModel, { id: req.params.id }, { ...req.query, select: { password: 0 } })
    let postRes
    if (hooks.readOneAdmin?.post) {
      postRes = await hooks.readOneAdmin.post(req.params, req.body, response.result)
    }
    return postRes || response
  })

  apiServer.delete('/v1/admins/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'delete' }])
    const adminCount = await AdminModel.count({})
    if (adminCount === 1) {
      throw new MethodNotAllowedError('Removing the last admin is not allowed')
    }
    const response = await deleteOne(AdminModel, { id: req.params.id }, { password: 0 })
    let postRes
    if (hooks.deleteAdmin?.post) {
      postRes = await hooks.deleteAdmin.post(req.params, req.body, response.result)
    }
    return postRes || response
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
    let postRes
    if (hooks.permissionFor?.post) {
      postRes = await hooks.permissionFor.post(req.params, req.body, token)
    }
    return postRes || {
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
    let postRes
    if (hooks.accessToken?.post) {
      postRes = await hooks.accessToken.post(req.params, req.body, token)
    }
    return postRes || {
      status: 200,
      result: {
        accessToken: token
      }
    }
  })

  apiServer.patch('/v1/admins/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin', user: { _id: req.params.id } }])
    const response = await patchOne(AdminModel, { id: req.params.id }, { name: req.body.name })
    let postRes
    if (hooks.updateName?.post) {
      postRes = await hooks.updateName.post(req.params, req.body, response.result)
    }
    return postRes || {
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
    const response = await patchOne(AdminModel, { id: req.params.id }, { password: hash })
    let postRes
    if (hooks.updatePassword?.post) {
      postRes = await hooks.updatePassword.post(req.params, req.body, response.result)
    }
    return postRes || {
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
    let postRes
    if (hooks.updateEmail?.post) {
      postRes = await hooks.updateEmail.post(req.params, req.body, mail)
    }
    return postRes || {
      status: 200,
      result: {
        success: true,
        info: mail.result.info
      }
    }
  })

  apiServer.patch('/v1/admins/:id/email-confirm', async req => {
    const data = await allowAccessTo(req, secrets, [{ type: 'verfiy-email', user: { _id: req.params.id } }])
    const response = await patchOne(AdminModel, { id: req.params.id }, { email: data.newEmail })
    let postRes
    if (hooks.confirmEmail?.post) {
      postRes = await hooks.confirmEmail.post(req.params, req.body, response.result)
    }
    return postRes || {
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
    const response = await patchOne(AdminModel, { id: req.params.id }, { profilePicture: process.env.CDN_BASE_URL + result.Key })
    let postRes
    if (hooks.addProfilePicture?.post) {
      postRes = await hooks.addProfilePicture.post(req.params, req.body, response.result)
    }
    return postRes || {
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
    const response = await patchOne(AdminModel, { id: req.params.id }, { profilePicture: null })
    let postRes
    if (hooks.deleteProfilePicture?.post) {
      postRes = await hooks.deleteProfilePicture.post(req.params, req.body, response.result)
    }
    return postRes || {
      status: 200,
      result: {
        success: true
      }
    }
  })
}
