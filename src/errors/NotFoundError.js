import ApiError from './ApiError.js'

export default class NotFoundError extends ApiError {
  constructor (message) {
    super(404, 'NOT_FOUND', message)
  }
}
