import ApiError from './ApiError.js'

export default class AuthorizationError extends ApiError {
  constructor (message) {
    super(403, 'AUTHORIZATION_ERROR', message)
  }
}
