import ApiError from './ApiError.js'

export default class AuthenticationError extends ApiError {
  constructor (name, message) {
    super(401, name, message)
  }
}
