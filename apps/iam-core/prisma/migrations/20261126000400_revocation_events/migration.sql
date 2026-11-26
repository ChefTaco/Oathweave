-- Session revocation events for the HiveEvent feed (GET /api/v1/hive/events). The integer
-- sequence is the feed cursor; rows hold identifiers only and are pruned after seven days.
CREATE TABLE "revocation_events" (
    "seq" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "sessionId" TEXT,
    "userId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "occurredAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX "revocation_events_id_key" ON "revocation_events"("id");
CREATE INDEX "revocation_events_occurredAt_idx" ON "revocation_events"("occurredAt");
