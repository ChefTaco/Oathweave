import argon2 from 'argon2'
import { prisma } from '../db/client.js'
import { parseClientPolicies } from './client-policy-schema.js'
import {
  MANAGED_CLIENT_DESCRIPTION,
  parseMachineClientSecrets,
  reconcileMachineClients,
  type ManagedClientStore,
  type ReconcileResult,
  type SecretHasher,
} from './machine-client-secrets.js'

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
}

export const prismaManagedClientStore: ManagedClientStore = {
  findById: (id) =>
    prisma.client.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        clientType: true,
        grantTypes: true,
        redirectUris: true,
        secretHash: true,
        active: true,
      },
    }),
  findByName: (name) =>
    prisma.client.findUnique({ where: { name }, select: { id: true } }),
  create: async ({ id, secretHash }) => {
    await prisma.client.create({
      data: {
        id,
        name: id,
        description: MANAGED_CLIENT_DESCRIPTION,
        secretHash,
        active: true,
        clientType: 'confidential',
        firstParty: true,
        redirectUris: '[]',
        grantTypes: '["client_credentials"]',
      },
    })
  },
  updateSecretHash: async (id, secretHash) => {
    await prisma.client.update({ where: { id }, data: { secretHash } })
  },
}

export const argon2Hasher: SecretHasher = {
  hash: (secret) => argon2.hash(secret, ARGON2_OPTIONS),
  verify: (hash, secret) => argon2.verify(hash, secret),
}

/** Startup step: the configured machine clients exist with their configured secrets. */
export async function reconcileConfiguredMachineClients(
  source: Record<string, string | undefined> = process.env,
): Promise<ReconcileResult[]> {
  const secrets = parseMachineClientSecrets(
    source['IAM_MACHINE_CLIENT_SECRETS'],
    parseClientPolicies(source['IAM_MACHINE_CLIENT_POLICIES']),
  )
  if (Object.keys(secrets).length === 0) return []
  return reconcileMachineClients(secrets, prismaManagedClientStore, argon2Hasher)
}
