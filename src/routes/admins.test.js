import crypto from 'crypto'

import mongoose from 'mongoose'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'

import createMongooseMemoryServer from 'mongoose-memory'

import createServer from './index.js'
import Admin from '../models/Admin.js'
import aws from '../helpers/awsBucket.js'
import StaticServer from 'static-server'

import path from 'path'
import { fileURLToPath } from 'url'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const bucketName = process.env.AWS_BUCKET_NAME
const s3 = await aws()

const secrets = process.env.SECRETS.split(' ')
const __dirname = path.dirname(fileURLToPath(import.meta.url))

const server = new StaticServer({
  rootPath: './tmp/' + process.env.AWS_BUCKET_NAME, // required, the root of the server file tree
  port: parseInt(process.env.TEST_STATIC_SERVER_URL.split(':')[2]), // required, the port to listen
  name: process.env.TEST_STATIC_SERVER_URL
})

describe('/v1/admins/ ', () => {
  let app
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')

    app = createServer()
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
    await server.stop()
  })

  afterAll(async () => {
    await s3.deleteBucket({ Bucket: bucketName }).promise()

    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  // get admin list tests
  test('success get admin list  /v1/admins/', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const user3 = new Admin({ email: 'user3@gmail.com', name: 'user3' })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.count).toBe(3)
  })

  test('unAuthorized header  /v1/admins/', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // get spicific admin tests
  test('success get admin  /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.email).toBe(user1.email)
  })

  test('unAuthorized header /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // delete admin tests
  test('success delete admin /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('delete admin permission needed error /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .delete('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  test('success get permission ', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/admins/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(200)
  })

  test('get permission error wrong Password ', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/admins/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'wrongPassword' })

    expect(res.body.status).toBe(401)
  })

  test('delete last admin error /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(405)
  })

  test('unAuthorized header for delete /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .delete('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // access Token tests
  test('success get access-token /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('success refresh access-token /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('access-token unAuthorized header /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  test('access-token unAuthorized user /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // update admin tests
  test('update name /v1/admins/:id/name', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'user3' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('update password success /v1/admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('update password unAuthorized user  /v1/admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('update password wrong newPasswordAgain validation error  /v1/admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'user11PasswordUpdated' })

    expect(res.body.status).toBe(400)
  })

  test('update password wrong password authorization error  /v1/admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password_wrong', newPassword: 'user11PasswordUpdated', newPasswordAgain: 'user11PasswordUpdated' })

    expect(res.body.status).toBe(403)
    expect(res.body.error.message).toBe('Wrong password.')
  })

  test('success patch email req send  /v1/admins/:id/email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate@gmail.com' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)

    const messageUrl = nodemailer.getTestMessageUrl(res.body.result.info)

    const html = await fetch(messageUrl).then(response => response.text())
    const regex = /<a[\s]+id=\\"verifyEmailLink\\"[^\n\r]*\?token&#x3D([^"&]+)">/g
    const found = html.match(regex)[0]
    const tokenPosition = found.indexOf('token&#x3D')
    const endTagPosition = found.indexOf('\\">')
    const htmlToken = found.substring(tokenPosition + 11, endTagPosition)
    const verifiedToken = jwt.verify(htmlToken, secrets[0], { algorithms: ['none'] })

    expect(htmlToken).toBeDefined()
    expect(verifiedToken.type).toBe('verfiy-email')
    expect(verifiedToken.newEmail).toBe('userUpdate@gmail.com')
  })

  test('patch email req send error email exist /v1/admins/:id/email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'user2@gmail.com', newEmailAgain: 'user2@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('patch email req send error email don\'t match /v1/admins/:id/email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'updateEmail@gmail.com', newEmailAgain: 'updateEmail2@gmail.com' })

    expect(res.body.status).toBe(400)
  })

  test('update email success /v1/admins/:id/email-confirm', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'verfiy-email', user: { _id: user1._id }, newEmail: 'userUpdate@gmail.com' }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/email-confirm')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('success upload profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app).post(`/v1/admins/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    const adminData = await request(app)
      .get('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    await server.start()
    const pic = await fetch(adminData.body.result.profilePicture)
    expect(pic.status).toBe(200)
    expect(res.body.status).toBe(200)
  })

  test('success delete profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const uploadRes = await request(app).post(`/v1/admins/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    await server.start()
    const picBeforeDelete = await fetch(uploadRes.body.result.profilePicture)
    expect(picBeforeDelete.status).toBe(200)

    const res = await request(app).delete(`/v1/admins/${user1._id}/profile-picture `)
      .set('authorization', 'Bearer ' + token).send()

    const pic = await fetch(uploadRes.body.result.profilePicture)
    expect(pic.status).toBe(404)
    expect(res.body.status).toBe(200)
  })
})
