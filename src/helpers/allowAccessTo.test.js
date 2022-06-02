import jwt from 'jsonwebtoken'

import allowAccessTo from './allowAccessTo.js'

import AuthenticationError from '../errors/AuthenticationError.js'
import AuthorizationError from '../errors/AuthorizationError.js'

const secrets = ['testsecret1', 'testsecret2']

describe('allowAccessTo', () => {
  test('authorization header missing', () => {
    const mockReq = { headers: { } }
    expect(() => allowAccessTo(mockReq, secrets)).toThrow(new AuthenticationError('Authorization header is missing.'))
  })

  test('authorization header is not in bearer schema', () => {
    const token = jwt.sign({ type: 'valid' }, secrets[0])
    const mockReq = { headers: { authorization: `${token}` } }
    expect(() => allowAccessTo(mockReq, secrets)).toThrow(new AuthenticationError('Authorization header should use the \'Bearer\' schema.'))
  })

  test('authorization failed', () => {
    const token = jwt.sign({ type: 'valid' }, 'invalidsecret')
    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    expect(() => allowAccessTo(mockReq, secrets)).toThrow(new AuthorizationError('Authorization failed.'))
  })

  test('auth success with the first secret', () => {
    const token = jwt.sign({ type: 'valid', something: 'else' }, secrets[0])
    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    expect(() => allowAccessTo(mockReq, secrets, [{ type: 'valid', something: 'else' }])).not.toThrow()

    const tokenResult = allowAccessTo(mockReq, secrets, [{ type: 'valid', something: 'else' }])
    expect(tokenResult.type).toBe('valid')
    expect(tokenResult.something).toBe('else')
  })

  test('auth success with the second secret', () => {
    const token = jwt.sign({ type: 'valid', something: 'else' }, secrets[1])
    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    expect(() => allowAccessTo(mockReq, secrets, [{ type: 'valid', something: 'else' }])).not.toThrow()

    const tokenResult = allowAccessTo(mockReq, secrets, [{ type: 'valid', something: 'else' }])
    expect(tokenResult.type).toBe('valid')
    expect(tokenResult.something).toBe('else')
  })

  test('not allowed type', () => {
    const token = jwt.sign({ type: 'notallowedtype' }, secrets[0])

    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    const accessList = [
      { type: 'backend' },
      { type: 'user', accountId: 4 }
    ]

    expect(() => allowAccessTo(mockReq, secrets, accessList)).toThrow(new AuthorizationError('Permission denied.'))
  })

  test('not allowed accountId', () => {
    const token = jwt.sign({ type: 'user', accountId: 'somethingelse' }, secrets[0])

    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    const accessList = [
      { type: 'backend' },
      { type: 'user', accountId: 4 }
    ]

    expect(() => allowAccessTo(mockReq, secrets, accessList)).toThrow(new AuthenticationError('Permission denied.'))
  })

  test('allowed type', () => {
    const token = jwt.sign({ type: 'backend' }, secrets[0])

    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    const accessList = [
      { type: 'backend' },
      { type: 'user', accountId: 4 }
    ]

    expect(() => allowAccessTo(mockReq, secrets, accessList)).not.toThrow()
  })

  test('allowed type with accountId', () => {
    const token = jwt.sign({ type: 'user', accountId: 4 }, secrets[0])

    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    const accessList = [
      { type: 'backend' },
      { type: 'user', accountId: 4 }
    ]

    expect(() => allowAccessTo(mockReq, secrets, accessList)).not.toThrow()
  })

  test('returns the content of the token', () => {
    const token = jwt.sign({ type: 'user', accountId: 4 }, secrets[0])

    const mockReq = { headers: { authorization: `Bearer ${token}` } }
    const accessList = [
      { type: 'backend' },
      { type: 'user', accountId: 4 }
    ]

    const tokenData = allowAccessTo(mockReq, secrets, accessList)

    expect(tokenData.type).toBe('user')
    expect(tokenData.accountId).toBe(4)
  })
})
