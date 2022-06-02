import ApiError from './ApiError.js'

export default class AuthenticationError extends ApiError {
  constructor (message) {
    super(401, 'AUTHENTICATION_ERROR', message)
  }
}
