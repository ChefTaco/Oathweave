#!/usr/bin/env bash
# test-iam-api.sh — End-to-end IAM API verification through the HiveXUI admin proxy
#
# Signs in with an existing admin session, never a password: sign in to HiveXUI in
# a browser (through Oathweave's sign-in page), copy the session cookie as
# `name=value` into an owner-only file, and pass that file. The script reads it
# into a private header file, so the cookie never appears in the process list,
# and tests the IAM endpoints through the /api/iam route (the path the browser uses).
#
# Usage:
#   HIVE_SESSION_COOKIE_FILE=<file> bash scripts/test-iam-api.sh [DASHBOARD_URL]
#
# DASHBOARD_URL defaults to $HIVE_PUBLIC_URL (e.g. https://hive.example.com).

set -euo pipefail

DASHBOARD_URL="${1:-${HIVE_PUBLIC_URL:-}}"
COOKIE_FILE="${HIVE_SESSION_COOKIE_FILE:-}"
PASS=0
FAIL=0
TOTAL=0

if [[ -z "$DASHBOARD_URL" ]]; then
  echo "ERROR: pass DASHBOARD_URL as the first argument or set HIVE_PUBLIC_URL"
  exit 1
fi
if [[ -z "$COOKIE_FILE" ]]; then
  echo "ERROR: set HIVE_SESSION_COOKIE_FILE to an owner-only file holding the HiveXUI session cookie (name=value)"
  exit 1
fi
if [[ ! -f "$COOKIE_FILE" || -L "$COOKIE_FILE" || ! -r "$COOKIE_FILE" ]]; then
  echo "ERROR: HIVE_SESSION_COOKIE_FILE must be a readable regular file"
  exit 1
fi
if (( (8#$(stat -c %a "$COOKIE_FILE") & 077) != 0 )); then
  echo "ERROR: HIVE_SESSION_COOKIE_FILE must be owner-only (chmod 600)"
  exit 1
fi
COOKIE_VALUE="$(head -n 1 "$COOKIE_FILE" | tr -d '\r')"
if [[ ! "$COOKIE_VALUE" =~ ^[^=[:space:]]+=[^[:space:]]+$ ]]; then
  echo "ERROR: HIVE_SESSION_COOKIE_FILE must hold one name=value cookie"
  exit 1
fi
HEADER_FILE="$(mktemp)"
chmod 600 "$HEADER_FILE"
printf 'Cookie: %s\n' "$COOKIE_VALUE" > "$HEADER_FILE"
unset COOKIE_VALUE

# ─── Helpers ──────────────────────────────────────────────────────────
cleanup() { rm -f "$HEADER_FILE"; }
trap cleanup EXIT

assert_contains() {
  local label="$1" body="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$body" | grep -qi "$expected"; then
    echo "  ✓ $label"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $label — expected '$expected' not found"
    FAIL=$((FAIL + 1))
  fi
}

assert_status() {
  local label="$1" status="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if [[ "$status" -eq "$expected" ]]; then
    echo "  ✓ $label (HTTP $status)"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $label — expected HTTP $expected, got $status"
    FAIL=$((FAIL + 1))
  fi
}

assert_json_field() {
  local label="$1" body="$2" field="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$field' in d" 2>/dev/null; then
    echo "  ✓ $label"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $label — field '$field' not present in response"
    FAIL=$((FAIL + 1))
  fi
}

assert_json_count() {
  local label="$1" body="$2" field="$3" min="$4"
  TOTAL=$((TOTAL + 1))
  local count
  count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('$field', [])))" 2>/dev/null || echo "0")
  if [[ "$count" -ge "$min" ]]; then
    echo "  ✓ $label ($count items)"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $label — expected ≥$min items in '$field', got $count"
    FAIL=$((FAIL + 1))
  fi
}

assert_json_number() {
  local label="$1" body="$2" field="$3" min="$4"
  TOTAL=$((TOTAL + 1))
  local val
  val=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field', 0))" 2>/dev/null || echo "0")
  if [[ "$val" -ge "$min" ]]; then
    echo "  ✓ $label ($val)"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $label — expected $field ≥ $min, got $val"
    FAIL=$((FAIL + 1))
  fi
}

proxy_get() {
  local path="$1"
  curl --silent --show-error -H @"$HEADER_FILE" "$DASHBOARD_URL/api/iam/$path" 2>/dev/null
}

proxy_get_status() {
  local path="$1"
  curl --silent --show-error -o /dev/null -w '%{http_code}' -H @"$HEADER_FILE" "$DASHBOARD_URL/api/iam/$path" 2>/dev/null
}

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  IAM API End-to-End Test"
echo "  Dashboard: $DASHBOARD_URL"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ─── 1. Session ───────────────────────────────────────────────────────
echo "▸ Session"
SESSION_STATUS=$(curl --silent --show-error -o /dev/null -w '%{http_code}' -H @"$HEADER_FILE" "$DASHBOARD_URL/api/auth/me")
assert_status "Admin session accepted" "$SESSION_STATUS" 200
echo ""

# ─── 2. Health ────────────────────────────────────────────────────────
echo "▸ Health"
HEALTH=$(proxy_get "health")
assert_json_field "Returns status field" "$HEALTH" "status"
assert_contains "Status is healthy" "$HEALTH" "healthy"
assert_json_field "Returns version" "$HEALTH" "version"
assert_json_field "Returns uptime" "$HEALTH" "uptime"
echo ""

# ─── 3. Users ─────────────────────────────────────────────────────────
echo "▸ Users"
USERS_STATUS=$(proxy_get_status "users")
assert_status "Users endpoint accessible" "$USERS_STATUS" 200
USERS=$(proxy_get "users")
assert_json_count "Has seeded users" "$USERS" "users" 1
assert_contains "Contains admin user" "$USERS" "admin"
echo ""

# ─── 4. Roles ─────────────────────────────────────────────────────────
echo "▸ Roles"
ROLES_STATUS=$(proxy_get_status "roles")
assert_status "Roles endpoint accessible" "$ROLES_STATUS" 200
ROLES=$(proxy_get "roles")
assert_json_count "Has system roles" "$ROLES" "roles" 5
assert_contains "Has SUPER_ADMIN role" "$ROLES" "SUPER_ADMIN"
assert_contains "Has IAM_ADMIN role" "$ROLES" "IAM_ADMIN"
assert_contains "Has OPERATOR role" "$ROLES" "OPERATOR"
echo ""

# ─── 5. Service Accounts ─────────────────────────────────────────────
echo "▸ Service Accounts"
SA_STATUS=$(proxy_get_status "service-accounts")
assert_status "Service Accounts endpoint accessible" "$SA_STATUS" 200
echo ""

# ─── 6. Clients ──────────────────────────────────────────────────────
echo "▸ Clients"
CLIENTS_STATUS=$(proxy_get_status "clients")
assert_status "Clients endpoint accessible" "$CLIENTS_STATUS" 200
CLIENTS=$(proxy_get "clients")
assert_json_count "Has seeded clients" "$CLIENTS" "clients" 1
assert_contains "Has hive client" "$CLIENTS" "hive"
echo ""

# ─── 7. Sessions ─────────────────────────────────────────────────────
echo "▸ Sessions"
SESSIONS_STATUS=$(proxy_get_status "sessions")
assert_status "Sessions endpoint accessible" "$SESSIONS_STATUS" 200
SESSIONS=$(proxy_get "sessions")
assert_json_count "Has active sessions" "$SESSIONS" "sessions" 1
echo ""

# ─── 8. Audit Stats ──────────────────────────────────────────────────
echo "▸ Audit Stats"
STATS_STATUS=$(proxy_get_status "audit/stats")
assert_status "Audit stats accessible" "$STATS_STATUS" 200
STATS=$(proxy_get "audit/stats")
assert_json_field "Has totalEvents" "$STATS" "totalEvents"
assert_json_field "Has successCount" "$STATS" "successCount"
assert_json_field "Has failureCount" "$STATS" "failureCount"
assert_json_number "Total events > 0" "$STATS" "totalEvents" 1
echo ""

# ─── 9. Audit Events ─────────────────────────────────────────────────
echo "▸ Audit Events"
AUDIT_STATUS=$(proxy_get_status "audit?page=1&limit=5")
assert_status "Audit events accessible" "$AUDIT_STATUS" 200
AUDIT=$(proxy_get "audit?page=1&limit=5")
assert_json_count "Has audit events" "$AUDIT" "events" 1
echo ""

# ─── 10. System Users ────────────────────────────────────────────────
echo "▸ System Users"
SYSUSERS_STATUS=$(proxy_get_status "system-users")
assert_status "System users accessible" "$SYSUSERS_STATUS" 200
echo ""

# ─── Summary ──────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  ✅ ALL $TOTAL TESTS PASSED"
else
  echo "  ❌ $FAIL/$TOTAL FAILED ($PASS passed)"
fi
echo "═══════════════════════════════════════════════════════════"
echo ""

exit "$FAIL"
