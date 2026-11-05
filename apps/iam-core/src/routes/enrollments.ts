import { Hono } from 'hono'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/rbac.js'
import { requireRecentSession } from '../middleware/recent-session.js'
import { EnrollmentLifecycleSchema, EnrollmentRequestSchema } from '../schemas/enrollments.js'
import { parseBody } from '../utils/validate.js'
import { assertMayAssignRoles, assertMayManageServiceAccount, resolveActor } from '../services/privilege-guard.js'
import { enrollmentSettings, enrollmentConfigurations, type EnrollmentSettings, enrollmentStore, enrollmentWrite, runEnrollment, acknowledgeEnrollment } from '../services/enrollment-runtime.js'
import { logAuditEvent } from '../services/audit-service.js'
import { ApiError } from '../types/index.js'

export const enrollmentsRouter = new Hono<{ Variables: { enrollment: EnrollmentSettings } }>()
enrollmentsRouter.use('*', authMiddleware)
enrollmentsRouter.use('*', async (c, next) => {
  c.header('Cache-Control','no-store')
  if (!c.req.path.endsWith('/enrollments/installations')) {
    const settings = enrollmentSettings(c.req.query('installationId'),c.get('principal').sub)
    if (!settings) throw new ApiError(503,'ENROLLMENT_UNCONFIGURED','This authority has no configured product enrollment APIs')
    c.set('enrollment',settings)
  }
  await next()
})
enrollmentsRouter.get('/installations',requirePermission('iam:sa:read'),c => c.json({ installations: Object.values(enrollmentConfigurations()).filter(settings=>!settings.operatorSubjects || settings.operatorSubjects.includes(c.get('principal').sub)).map(settings=>settings.installationId) }))
enrollmentsRouter.get('/', requirePermission('iam:sa:read'), c => {
  const store = enrollmentStore(c.get('enrollment')), principal = c.get('principal')
  return c.json({ installationId: store.installationId, data: store.list().map(enrollment => {
    let policy: Record<string, unknown> = {}; try { policy = JSON.parse(enrollment.requestJson) as Record<string, unknown> } catch { /* Imported malformed policies stay review-only. */ }
    const identifiers = { iamServiceAccountId: enrollment.iamId, routerClientKeyId: enrollment.routerKeyId, memoryAgentId: enrollment.memoryId }
    return { id: enrollment.actorId, kind: 'service-account', label: typeof policy.displayName === 'string' ? policy.displayName : enrollment.actorId, status: enrollment.status === 'contained' ? 'inactive' : 'active', sources: Object.entries(identifiers).filter(([, id]) => id).map(([key]) => ({ iamServiceAccountId: 'iam', routerClientKeyId: 'router', memoryAgentId: 'memory' })[key]), identifiers, capabilities: enrollment.ownerId === principal.sub ? ['credential:rotate', 'credential:disable'] : [], linkedResourceCount: Object.values(identifiers).filter(Boolean).length, lastActivityAt: null, enrollmentStatus: enrollment.status, credentialExpiresAt: enrollment.credentialExpiresAt ? new Date(enrollment.credentialExpiresAt).toISOString() : null, latestOperation: enrollment.ownerId === principal.sub ? store.latest(enrollment.actorId) : null, legacyReceiptAvailable: enrollment.ownerId === principal.sub && !!enrollment.encryptedSecrets && (enrollment.receiptExpiresAt ?? 0) > Date.now() }
  }) })
})
enrollmentsRouter.post('/', requirePermission('iam:sa:write'), requireRecentSession, async c => {
  const body = await parseBody(c, EnrollmentRequestSchema)
  await assertMayAssignRoles(await resolveActor(c), body.roleIds, 'enroll this service identity')
  const settings = c.get('enrollment'); if (!settings) throw new ApiError(503, 'ENROLLMENT_UNCONFIGURED', 'Configure product-owned enrollment APIs first')
  const result = await runEnrollment(enrollmentStore(c.get('enrollment')), settings, c.get('principal'), body.agentId, 'enroll', body)
  await logAuditEvent({ eventType: 'identity.enrollment', category: 'SERVICE_ACCOUNT', actorId: c.get('principal').sub, actorType: 'USER', action: 'enroll', resourceType: 'actor', resourceId: body.agentId, detail: { operationId: result.operationId, ok: result.ok, steps: result.steps }, source: 'oathweave-enrollment' })
  return c.json(result, result.ok ? 201 : 207)
})
for (const action of ['rotate', 'disable'] as const) enrollmentsRouter.post('/:actorId/' + action, requirePermission('iam:sa:write'), requireRecentSession, async c => {
  const body = await parseBody(c, EnrollmentLifecycleSchema), actorId = c.req.param('actorId')!, store = enrollmentStore(c.get('enrollment')), enrollment = store.get(actorId)
  if (enrollment.iamId) await assertMayManageServiceAccount(await resolveActor(c), enrollment.iamId, action + ' this service identity')
  const settings = c.get('enrollment'); if (!settings) throw new ApiError(503, 'ENROLLMENT_UNCONFIGURED', 'Configure product-owned enrollment APIs first')
  const result = await runEnrollment(store, settings, c.get('principal'), actorId, action, undefined, body.operationId)
  await logAuditEvent({ eventType: 'identity.' + action, category: 'SERVICE_ACCOUNT', actorId: c.get('principal').sub, actorType: 'USER', action, resourceType: 'actor', resourceId: actorId, detail: { operationId: result.operationId, ok: result.ok, steps: result.steps }, source: 'oathweave-enrollment' })
  return c.json(result, result.ok ? 200 : 207)
})
enrollmentsRouter.delete('/:actorId/operations/:operationId/receipt', requirePermission('iam:sa:write'), requireRecentSession, async c => {
  const settings = c.get('enrollment'); if (!settings) throw new ApiError(503, 'ENROLLMENT_UNCONFIGURED', 'Configure product-owned enrollment APIs first')
  await acknowledgeEnrollment(enrollmentStore(c.get('enrollment')), settings, c.get('principal'), c.req.param('actorId')!, c.req.param('operationId')!)
  return c.json({ ok: true })
})
enrollmentsRouter.get('/:actorId/operations/:operationId', requirePermission('iam:sa:write'), requireRecentSession, c => {
  const store = enrollmentStore(c.get('enrollment')), operation = store.operation(c.req.param('operationId')!)
  if (operation.actorId !== c.req.param('actorId') || operation.ownerId !== c.get('principal').sub) throw new ApiError(404, 'NOT_FOUND', 'Owned operation not found')
  return c.json(store.result(operation.id))
})
enrollmentsRouter.get('/:actorId/receipt', requirePermission('iam:sa:write'), requireRecentSession, async c => c.json(await enrollmentWrite(() => enrollmentStore(c.get('enrollment')).legacyReceipt(c.get('principal').sub, c.req.param('actorId')!))))
enrollmentsRouter.post('/:actorId/operations/:operationId/resume', requirePermission('iam:sa:write'), requireRecentSession, async c => {
  const store = enrollmentStore(c.get('enrollment')), actorId = c.req.param('actorId')!, operation = store.operation(c.req.param('operationId')!)
  if (operation.actorId !== actorId || operation.ownerId !== c.get('principal').sub) throw new ApiError(404, 'NOT_FOUND', 'Owned operation not found')
  const policy = EnrollmentRequestSchema.parse(JSON.parse(store.get(actorId).requestJson))
  await assertMayAssignRoles(await resolveActor(c), policy.roleIds, 'resume this explicitly scoped service identity')
  const settings = c.get('enrollment'); if (!settings) throw new ApiError(503, 'ENROLLMENT_UNCONFIGURED', 'Configure product-owned enrollment APIs first')
  const result = await runEnrollment(store, settings, c.get('principal'), actorId, operation.action, operation.action === 'enroll' ? policy : undefined, operation.id)
  return c.json(result, result.ok ? 200 : 207)
})
enrollmentsRouter.delete('/:actorId/receipt', requirePermission('iam:sa:write'), requireRecentSession, async c => {
  await enrollmentWrite(() => enrollmentStore(c.get('enrollment')).acknowledgeLegacyReceipt(c.get('principal').sub, c.req.param('actorId')!))
  return c.json({ ok: true })
})
