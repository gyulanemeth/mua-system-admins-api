import mongoose from 'mongoose'
import sendEmail from 'aws-ses-send-email'

import routes from './routes/index.js'

const api = routes(sendEmail, process.env.MAX_FILE_SIZE)

await mongoose.connect(process.env.MONGO_URL).catch(e => console.error(e))

api.listen(process.env.PORT, () => {
  console.log(`MUA System Admins API is listening on ${process.env.PORT}`)
})
