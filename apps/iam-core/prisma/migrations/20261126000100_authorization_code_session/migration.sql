-- The session an authorization code's exchange issued tokens for, so a replay of the code can
-- revoke them (RFC 6749 §4.1.2, RFC 9700 §4.2.4).
ALTER TABLE "authorization_codes" ADD COLUMN "issuedSessionId" TEXT;
