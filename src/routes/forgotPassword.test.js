import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'

import createServer from './index.js'

import Admin from '../models/Admin.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

describe('/v1/forgot-password/', () => {
  let app
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')

    app = createServer()
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
  test('success send forget password  /v1/forgot-password/send', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/forgot-password/send')
      .send({ email: user2.email })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)

    // testing email sent

    const messageUrl = nodemailer.getTestMessageUrl(res.body.result.info)

    const html = await fetch(messageUrl).then(response => response.text())
    const regex = /<a[\s]+id=\\"forgetPasswordLink\\"[^\n\r]*\?token=([^"&]+)">/g
    const found = html.match(regex)[0]
    const tokenPosition = found.indexOf('token=')
    const endTagPosition = found.indexOf('\\">')
    const htmlToken = found.substring(tokenPosition + 6, endTagPosition)
    const verifiedToken = jwt.verify(htmlToken, secrets[0])
    expect(htmlToken).toBeDefined()
    expect(verifiedToken.type).toBe('forgot-password')
    expect(verifiedToken.user.email).toBe(user2.email)
  })

  test('send forget password error user not found  /v1/forgot-password/send', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const res = await request(app)
      .post('/v1/forgot-password/send')
      .send({ email: 'user2@gmail.com' })
    expect(res.body.status).toBe(401)
  })

  // forget password  reset tests

  test('success reset forget password  /v1/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(200)
  })

  test(' reset forget password validation error  /v1/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongeNewPassword' })
    expect(res.body.status).toBe(400)
  })

  test('reset forget password unAuthorized header  /v1/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(403)
  })

  test('reset forget password user email does not exist  /v1/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()
    const token = jwt.sign({ type: 'forgot-password', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])
    const res = await request(app)
      .post('/v1/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(404)
  })
})
