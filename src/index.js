import mongoose from 'mongoose'

// import Admin from './models/Admin.js'
// import crypto from 'crypto'
import routes from './routes/index.js'
import dotenv from 'dotenv'
dotenv.config({ path: '../.env' })

const api = routes()

await mongoose.connect('mongodb://0.0.0.0:27017/mua-system-admins').catch(e => console.error(e))
/*
const hash1 = crypto.createHash('md5').update('user6Password').digest('hex')
const user1 = new Admin({ email: 'user6@gmail.com', name: 'user6', password: hash1 })
await user1.save()

const hash2 = crypto.createHash('md5').update('user7Password').digest('hex')
const user2 = new Admin({ email: 'user7@gmail.com', name: 'user7', password: hash2 })
await user2.save()
*/
api.listen(process.env.PORT, () => {
  console.log(`MUA System Admins API is listening on ${process.env.PORT}`)
})
