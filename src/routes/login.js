import { readOne } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'

export default (apiServer) => {
  apiServer.post('/v1/login', async req => {
    const response = await readOne(AdminModel)
    // check user and return auth
    return response
  })
}
