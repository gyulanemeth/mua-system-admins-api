import mongoose from 'mongoose'

const AdminSchema = new mongoose.Schema({
  name: { type: String },
  // email should be unique and should be in  example@example.com formate match: /.+\@.+\..+/,
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String }
}, { timestamps: true })

AdminSchema.index({ name: "text", email:"text" });
export default mongoose.model('Admin', AdminSchema)
