-- Oathweave owns coordination; product credentials remain product-owned.
CREATE TABLE "ActorEnrollment" (
  "actorId" TEXT NOT NULL PRIMARY KEY, "nativeActorId" TEXT NOT NULL, "ownerId" TEXT NOT NULL,
  "installationId" TEXT NOT NULL,
  "requestHash" TEXT NOT NULL, "requestJson" TEXT NOT NULL,
  "credentialExpiresAt" DATETIME,
  "iamId" TEXT, "routerKeyId" TEXT, "memoryId" TEXT,
  "encryptedSecrets" TEXT, "receiptExpiresAt" DATETIME,
  "leaseUntil" DATETIME, "status" TEXT NOT NULL DEFAULT 'pending',
  "updatedAt" DATETIME NOT NULL
);
CREATE TABLE "ActorLifecycleOperation" (
  "id" TEXT NOT NULL PRIMARY KEY, "operationId" TEXT NOT NULL, "installationId" TEXT NOT NULL, "bindingKey" TEXT NOT NULL,
  "actorId" TEXT NOT NULL, "ownerId" TEXT NOT NULL, "action" TEXT NOT NULL,
  "identifiersJson" TEXT NOT NULL, "stepsJson" TEXT NOT NULL DEFAULT '{}',
  "encryptedSecrets" TEXT, "receiptExpiresAt" DATETIME,
  "status" TEXT NOT NULL DEFAULT 'pending',
  "createdAt" DATETIME NOT NULL, "updatedAt" DATETIME NOT NULL
);
CREATE INDEX "ActorLifecycleOperation_bindingKey_status_idx" ON "ActorLifecycleOperation" ("bindingKey", "status");
CREATE TABLE "ActorLifecycleLease" (
  "bindingKey" TEXT NOT NULL PRIMARY KEY, "token" TEXT NOT NULL, "leaseUntil" DATETIME NOT NULL
);
CREATE TABLE "EnrollmentMigration" (
  "installationId" TEXT NOT NULL PRIMARY KEY, "sourceDigest" TEXT NOT NULL,
  "reviewDigest" TEXT NOT NULL, "importedAt" DATETIME NOT NULL,
  "provenanceJson" TEXT NOT NULL
);

CREATE UNIQUE INDEX "ActorEnrollment_installationId_nativeActorId_key" ON "ActorEnrollment" ("installationId", "nativeActorId");
CREATE UNIQUE INDEX "ActorLifecycleOperation_installationId_operationId_key" ON "ActorLifecycleOperation" ("installationId", "operationId");
