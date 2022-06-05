import mongoose from 'mongoose'

import routes from './routes/index.js'

import dotenv from 'dotenv'
dotenv.config({ path: '../.env' })

const api = routes()

mongoose.connect(process.env.MONGO_URL).catch(e => console.error(e))

api.listen(process.env.PORT, () => {
  console.log(`MUA System Admins API is listening on ${process.env.PORT}`)
})
