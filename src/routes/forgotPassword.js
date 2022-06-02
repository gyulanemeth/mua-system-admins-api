import { readOne } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'

export default (apiServer) => {
  apiServer.post('/v1/forgot-password/send', async req => {
    const response = await readOne(AdminModel)
    // check auth if user exist
    // send envitation email
    return response
  })

  apiServer.post('/v1/forgot-password/reset', async req => {
    const response = await readOne(AdminModel)
    // check auth if user exist
    // set new password
    return response
  })
}
