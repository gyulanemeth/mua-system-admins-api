import mongoose from 'mongoose'

const AdminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  // email should be unique and should be in  example@example.com formate match: /.+\@.+\..+/,
  email: { type: String, lowercase: true, required: true, unique: true },
  // password length more than 6 and should contain Capital and small letter and at least one digit and one special character
  password: { type: String, match: /(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&^_-]).{6,}/ }
}, { timestamps: true })

export default mongoose.model('Admin', AdminSchema)
