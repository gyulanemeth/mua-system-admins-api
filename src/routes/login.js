import crypto from 'crypto'

import jwt from 'jsonwebtoken'

import { list } from 'mongoose-crudl'
import { AuthenticationError } from 'standard-api-errors'

export default ({
  apiServer, AdminModel
}) => {
  const secrets = process.env.SECRETS.split(' ')
  apiServer.post('/v1/system-admins/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(AdminModel, { email: req.body.email, password: req.body.password }, { select: { password: 0 } })

    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid email or password')
    }

    const payload = {
      type: 'login',
      user: {
        _id: findUser.result.items[0]._id,
        email: findUser.result.items[0].email
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    return {
      status: 200,
      result: {
        loginToken: token
      }
    }
  })
}
