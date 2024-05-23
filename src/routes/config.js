import allowAccessTo from 'bearer-jwt-auth'

export default ({ apiServer }) => {
  const secrets = process.env.SECRETS.split(' ')
  apiServer.get('/v1/config', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    return {
      status: 200,
      result: {
        accountsApiUrl: process.env.ACCOUNTS_API_URL,
        accountsAppUrl: process.env.ACCOUNTS_APP_URL,
        appUrl: process.env.ADMIN_APP_URL
      }
    }
  })
}
