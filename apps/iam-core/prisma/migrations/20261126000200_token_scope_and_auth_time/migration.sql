-- The OAuth scope a refresh token was granted, so refreshed access tokens keep it and UserInfo
-- answers with the claims that scope allows (OpenID Connect Core §5.4).
ALTER TABLE "refresh_tokens" ADD COLUMN "scope" TEXT;
-- When the user behind an authorization code last authenticated, for the id_token auth_time claim.
ALTER TABLE "authorization_codes" ADD COLUMN "authTime" DATETIME;
