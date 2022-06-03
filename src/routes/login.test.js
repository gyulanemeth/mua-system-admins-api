import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'

import createServer from './index.js'


import AuthenticationError from '../errors/AuthenticationError.js'
import Admin from '../models/Admin.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)


describe('/v1/login/ ', () => {
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

  test('login with email and password', async () => {

      const hash1 = crypto.createHash('md5').update("user1Password").digest('hex')
      const user1 = new Admin({ email: 'user1@gmail.com', password: hash1 })
      await user1.save()

      const hash2 = crypto.createHash('md5').update("user2Password").digest('hex')
      const user2 = new Admin({ email: 'user2@gmail.com', password: hash2 })
      await user2.save()

      const res = await request(app)
        .post('/v1/tasks/')
        .send({email: user1.email, password: user1.password })
        console.log(res.body);
        expect(res).not.toThrow()
      expect(res.body.status).toBe(200)
    })


      test('login with wronge email', async () => {

          const hash1 = crypto.createHash('md5').update("user1Password").digest('hex')
          const user1 = new Admin({ email: 'user1@gmail.com', password: hash1 })
          await user1.save()

          const res = await request(app)
            .post('/v1/tasks/')
            .send({email: "user3@gmail.com", password: user1.password })
            console.log(res.body);
            expect(res).not.toThrow(new AuthenticationError('Invalid email or password'))
          expect(res.body.status).toBe(401)
        })

        test('login with wronge password', async () => {

            const hash1 = crypto.createHash('md5').update("user1Password").digest('hex')
            const user1 = new Admin({ email: 'user1@gmail.com', password: hash1 })
            await user1.save()

            const hash2 = crypto.createHash('md5').update("user2Password").digest('hex')
            const user2 = new Admin({ email: 'user2@gmail.com', password: hash2 })
            await user2.save()

            const res = await request(app)
              .post('/v1/tasks/')
              .send({email: user1.email, password: user2.password })
              console.log(res.body);
              expect(res).not.toThrow(new AuthenticationError('Invalid email or password'))
            expect(res.body.status).toBe(401)
          })


})
