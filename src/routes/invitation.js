import { readOne } from 'mongoose-crudl'
import AdminModel from '../models/Admin.js'

export default (apiServer) => {
  apiServer.post('/v1/invitation/send', async req => {
    const response = await readOne(AdminModel)
    // check auth if user exist
    // if not create user and send envitation email
    // if exist return error user exist
    return response
  })

  apiServer.post('/v1/invitation/accept', async req => {
    const response = await readOne(AdminModel)
    // check auth if user exist and don't have a password
    // if not create user and send envitation email
    // if exist return error user exist
    return response
  })
}
