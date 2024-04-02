import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import crypto from 'crypto'

import mongoose from 'mongoose'
import request from 'supertest'
import jwt from 'jsonwebtoken'

import createMongooseMemoryServer from 'mongoose-memory'

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
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

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
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ status: 400 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new Admin({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new Admin({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/forgot-password/send')
      .send({ email: user2.email })

    expect(res.body.status).toBe(400)
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
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongNewPassword' })
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
