import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'

import mongoose from 'mongoose'
import request from 'supertest'

import createMongooseMemoryServer from 'mongoose-memory'

import login from './login.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const TestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('/v1/login/ ', () => {
  let app
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    app = createApiServer((e) => {
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => {})
    login({ apiServer: app, AdminModel: TestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('login with email and password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/login')
      .send({ email: user1.email, password: 'user1Password' })
    expect(res.body.status).toBe(200)
  })

  test('login with wrong email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const res = await request(app)
      .post('/v1/login')
      .send({ email: 'user3@gmail.com', password: 'user1Password' })

    expect(res.statusCode).toBe(401)
  })

  test('login with wrong password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new TestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new TestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/login')
      .send({ email: user1.email, password: 'user3Password' })

    expect(res.statusCode).toBe(401)
  })
})
