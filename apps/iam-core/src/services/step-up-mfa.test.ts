import { beforeEach, expect, it, vi } from 'vitest'
const mock = vi.hoisted(() => ({
  find: vi.fn(),
  advance: vi.fn(),
  verify: vi.fn(),
  options: vi.fn(),
}))
vi.mock('../db/client.js', () => ({
  prisma: {
    webAuthnCredential: {
      findFirst: mock.find,
      findMany: vi.fn(async () => []),
      updateMany: mock.advance,
    },
  },
}))
vi.mock('./webauthn-service.js', () => ({
  verifyAuthentication: mock.verify,
  getAuthenticationOptions: mock.options,
}))
const { verifyStepUpPasskey } = await import('./step-up-mfa.js')
beforeEach(() => {
  mock.find.mockResolvedValue({
    id: 'fake-record',
    credentialId: 'fake-key',
    userId: 'fake-user',
    publicKey: 'fake-key-material',
    counter: 1,
    transports: '[]',
  })
  mock.verify.mockResolvedValue({
    verified: true,
    authenticationInfo: { newCounter: 2 },
  })
  mock.advance.mockResolvedValue({ count: 1 })
  vi.clearAllMocks()
})
it('binds step-up assertions to the current user and session, retaining the stored credential identity', async () => {
  await verifyStepUpPasskey('fake-user', 'fake-session', { id: 'fake-key' })
  expect(mock.find.mock.calls[0]?.[0].where.userId).toBe('fake-user')
  expect(mock.verify.mock.calls[0]?.[3]).toBe('fake-session:step-up')
  expect(mock.advance.mock.calls[0]?.[0].where).toEqual({
    id: 'fake-record',
    counter: 1,
  })
})
it('does not accept another account, invalid proof or a raced credential counter', async () => {
  mock.find.mockResolvedValueOnce(null)
  await expect(
    verifyStepUpPasskey('other-user', 'other-session', { id: 'fake-key' }),
  ).rejects.toThrow('Unknown')
  mock.verify.mockResolvedValueOnce({ verified: false })
  await expect(
    verifyStepUpPasskey('fake-user', 'fake-session', { id: 'fake-key' }),
  ).rejects.toThrow('Invalid')
  mock.advance.mockResolvedValueOnce({ count: 0 })
  await expect(
    verifyStepUpPasskey('fake-user', 'fake-session', { id: 'fake-key' }),
  ).rejects.toThrow('changed')
})
