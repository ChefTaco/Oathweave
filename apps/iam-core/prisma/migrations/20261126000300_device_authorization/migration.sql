-- OAuth 2.0 Device Authorization Grant (RFC 8628): one row per device sign-in, from the
-- device's request through a person's approval to the single token exchange.
CREATE TABLE "device_authorizations" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "deviceCodeHash" TEXT NOT NULL,
    "userCode" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scope" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "userId" TEXT,
    "authTime" DATETIME,
    "interval" INTEGER NOT NULL DEFAULT 5,
    "lastPolledAt" DATETIME,
    "expiresAt" DATETIME NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX "device_authorizations_deviceCodeHash_key" ON "device_authorizations"("deviceCodeHash");
CREATE UNIQUE INDEX "device_authorizations_userCode_key" ON "device_authorizations"("userCode");
CREATE INDEX "device_authorizations_expiresAt_idx" ON "device_authorizations"("expiresAt");
