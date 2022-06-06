import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'

import createServer from './index.js'

import Admin from '../models/Admin.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

describe('/v1/admins/ ', () => {
  let app
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')

    app = createServer()
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
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

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('delete last admin error /v1/admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

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

    const token = jwt.sign({ type: 'login', user: { id: user1._id } }, secrets[0])

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

    const token = jwt.sign({ type: 'admin', user: { id: user1._id } }, secrets[0])

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

    const token = jwt.sign({ type: 'admin', user: { id: user2._id } }, secrets[0])

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

    const token = jwt.sign({ type: 'admin', user: { id: user1._id } }, secrets[0])

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

    const token = jwt.sign({ type: 'admin', user: { id: user1._id } }, secrets[0])

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

    const token = jwt.sign({ type: 'admin', user: { id: user2._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('update password wronge newPasswordAgain validation error  /v1/admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'user11PasswordUpdated' })

    expect(res.body.status).toBe(400)
  })
})
