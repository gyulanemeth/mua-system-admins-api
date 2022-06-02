import ApiError from './ApiError.js'

export default class MethodNotAllowedError extends ApiError {
  constructor (message) {
    super(405, 'Method_Not_Allowed', message)
  }
}
