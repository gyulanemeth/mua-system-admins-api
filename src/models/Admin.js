import mongoose from 'mongoose'

const AdminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  // email should be unique and should be in  example@example.com formate match: /.+\@.+\..+/,
  email: { type: String, lowercase: true, required: true, unique: true },
  password: { type: String }
}, { timestamps: true })

export default mongoose.model('Admin', AdminSchema)
