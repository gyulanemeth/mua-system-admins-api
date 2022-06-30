import mongoose from 'mongoose'
import dotenv from 'dotenv'

import routes from './routes/index.js'


dotenv.config({ path: '../.env' })

const api = routes()

await mongoose.connect(process.env.MONGO_URL).catch(e => console.error(e))

api.listen(process.env.PORT, () => {
  console.log(`MUA System Admins API is listening on ${process.env.PORT}`)
})
