import ApiError from './ApiError.js'

export default class ValidationError extends ApiError {
  constructor (message) {
    super(400, 'VALIDATION_ERROR', message)
  }
}
