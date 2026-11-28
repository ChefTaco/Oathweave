/**
 * The `act` (actor) claim of a delegated token (RFC 8693 §4.1): who is acting for the subject.
 * `sub` names the current actor; a nested `act` names the prior actor in the chain.
 */
export interface ActorClaim {
  readonly sub: string
  /** The actor's client, when it differs from its subject. */
  readonly client_id?: string
  readonly act?: ActorClaim
}

/** Deepest actor chain Oathweave issues or accepts: an actor and the client that relayed it. */
export const MAX_ACTOR_DEPTH = 2

/** True when `value` is an `act` claim Oathweave could have issued. */
export function isActorClaim(value: unknown, depth = 1): value is ActorClaim {
  if (!value || typeof value !== 'object' || Array.isArray(value) || depth > MAX_ACTOR_DEPTH) return false
  const claim = value as Record<string, unknown>
  if (Object.keys(claim).some((key) => key !== 'sub' && key !== 'client_id' && key !== 'act')) return false
  if (typeof claim['sub'] !== 'string' || !claim['sub']) return false
  if (claim['client_id'] !== undefined && (typeof claim['client_id'] !== 'string' || !claim['client_id'])) return false
  return claim['act'] === undefined || isActorClaim(claim['act'], depth + 1)
}
