import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'

import mongoose from 'mongoose'
import request from 'supertest'
import jwt from 'jsonwebtoken'

import createMongooseMemoryServer from 'mongoose-memory'

import forgotPassword from './forgotPassword.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const TestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('/v1/system-admins/forgot-password/', () => {
  let app
  let secrets
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.NODE_ENV = 'development'
    process.env.SECRETS = 'verylongsecret1 verylongsecret2'
    process.env.ADMIN_BLUEFOX_VERIFY_EMAIL_TEMPLATE = ''
    process.env.ADMIN_BLUEFOX_FORGOT_PASSWORD_TEMPLATE = ''
    process.env.ADMIN_BLUEFOX_INVITATION_TEMPLATE = ''
    process.env.BLUEFOX_API_KEY = '<your_bluefox_api_key>'
    process.env.MAX_FILE_SIZE = '5242880'
    process.env.AWS_BUCKET_NAME = 'bluefox'
    process.env.AWS_FOLDER_NAME = 'mua-system-admins'
    process.env.AWS_BUCKET_PATH = './tmp/'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.CDN_BASE_URL = 'http://localhost:10006/'
    process.env.TEST_STATIC_SERVER_URL = 'http://localhost:10006/'
    process.env.ADMIN_APP_URL = 'http://admins.emailfox.link/'
    secrets = process.env.SECRETS.split(' ')
    app = createApiServer((e) => {
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => {})
    forgotPassword({ apiServer: app, AdminModel: TestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })
  // forget password  send tests
  test('success send forget password  /v1/system-admins/forgot-password/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: user2.email })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ status: 400 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: user2.email })

    expect(res.body.status).toBe(400)
  })

  test('send forget password error user not found  /v1/system-admins/forgot-password/send', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: 'user2@gmail.com' })
    expect(res.body.status).toBe(401)
  })

  // forget password  reset tests

  test('success reset forget password  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(200)
  })

  test(' reset forget password validation error  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongNewPassword' })
    expect(res.body.status).toBe(400)
  })

  test('reset forget password unAuthorized header  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(403)
  })

  test('reset forget password user email does not exist  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()
    const token = jwt.sign({ type: 'forgot-password', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])
    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(404)
  })
})
