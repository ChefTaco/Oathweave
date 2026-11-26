/** The claims Oathweave's id_tokens and UserInfo can carry, as discovery advertises them. */
export const ID_TOKEN_CLAIMS = [
  'sub',
  'iss',
  'aud',
  'exp',
  'iat',
  'auth_time',
  'nonce',
  'sid',
  'at_hash',
  'preferred_username',
  'name',
  'email',
  'email_verified',
  'roles',
] as const
