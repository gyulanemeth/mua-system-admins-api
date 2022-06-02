import ApiError from './ApiError.js'

export default class AuthorizationError extends ApiError {
  constructor (name, message) {
    super(403, name, message)
  }
}
