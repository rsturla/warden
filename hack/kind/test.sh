#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="agent-sandbox"
TEST_SERVER="http://test-server.agent-sandbox.svc"
PASS=0
FAIL=0

info()  { echo "==> $*"; }
pass()  { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

# Use test-agent pod (curl image). Fall back to any agent pod.
AGENT_POD=$(kubectl -n "$NAMESPACE" get pod test-agent -o name 2>/dev/null) || \
  AGENT_POD=$(kubectl -n "$NAMESPACE" get pods -l role=agent -o name 2>/dev/null | head -1)
if [ -z "$AGENT_POD" ]; then
  echo "ERROR: No agent pod found in namespace $NAMESPACE"
  kubectl -n "$NAMESPACE" get pods 2>/dev/null || true
  exit 1
fi

info "Using pod: $AGENT_POD"
kubectl -n "$NAMESPACE" wait --for=condition=Ready "$AGENT_POD" --timeout=120s
echo ""

# Helper: run curl in agent pod, return HTTP status code
agent_curl() {
  local code
  code=$(kubectl -n "$NAMESPACE" exec "$AGENT_POD" -- \
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" 2>/dev/null) || true
  echo "${code:-000}"
}

# Helper: run curl in agent pod, return body
agent_curl_body() {
  kubectl -n "$NAMESPACE" exec "$AGENT_POD" -- \
    curl -s --max-time 10 "$@" 2>/dev/null || true
}

# ========================================
# Policy enforcement — allow / deny
# ========================================

info "Test 1: GET /get via proxy (allowed)"
CODE=$(agent_curl "$TEST_SERVER/get")
if [ "$CODE" = "200" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 200)"; fi

info "Test 2: GET unknown host (denied — default-deny)"
CODE=$(agent_curl "http://not-allowed.example.com/")
if [ "$CODE" = "403" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 403)"; fi

info "Test 3: GET 169.254.169.254 (denied — metadata blocked)"
CODE=$(agent_curl "http://169.254.169.254/latest/meta-data/")
if [ "$CODE" = "403" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 403)"; fi

# ========================================
# Secret injection
# ========================================

info "Test 4: Verify injected Authorization header value"
BODY=$(agent_curl_body "$TEST_SERVER/headers")
if echo "$BODY" | grep -q "warden-injected-token-12345"; then
  pass "token present in echoed headers"
else
  fail "token missing"
  echo "  Body: $BODY"
fi

info "Test 5: No injection on non-injecting policy"
BODY=$(agent_curl_body "$TEST_SERVER/get")
if echo "$BODY" | grep -q "Authorization"; then
  fail "Authorization header present on non-injecting route"
else
  pass "no Authorization header on /get (correct)"
fi

# ========================================
# Method filtering
# ========================================

info "Test 6: POST /post (denied — only GET allowed)"
CODE=$(agent_curl -X POST "$TEST_SERVER/post")
if [ "$CODE" = "403" ]; then pass "POST returned $CODE"
else fail "POST returned $CODE (expected 403)"; fi

info "Test 7: POST /get (denied — POST method not in policy)"
CODE=$(agent_curl -X POST "$TEST_SERVER/get")
if [ "$CODE" = "403" ]; then pass "POST /get returned $CODE"
else fail "POST /get returned $CODE (expected 403)"; fi

info "Test 8: GET /get (allowed — confirm GET still works)"
CODE=$(agent_curl "$TEST_SERVER/get")
if [ "$CODE" = "200" ]; then pass "GET returned $CODE"
else fail "GET returned $CODE (expected 200)"; fi

# ========================================
# Path-based matching
# ========================================

info "Test 9: GET /api/v1/resource (allowed — path matches /api/v1/**)"
CODE=$(agent_curl "$TEST_SERVER/api/v1/resource")
if [ "$CODE" = "200" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 200)"; fi

info "Test 10: GET /api/v2/resource (denied — no matching path rule)"
CODE=$(agent_curl "$TEST_SERVER/api/v2/resource")
if [ "$CODE" = "403" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 403)"; fi

info "Test 11: GET /nonexistent (denied — path not in any policy)"
CODE=$(agent_curl "$TEST_SERVER/nonexistent")
if [ "$CODE" = "403" ]; then pass "returned $CODE"
else fail "returned $CODE (expected 403)"; fi

# ========================================
# HTTPS CONNECT (early rejection)
# ========================================

info "Test 12: HTTPS CONNECT to denied host (early 403 before TLS handshake)"
CONNECT_OUTPUT=$(kubectl -n "$NAMESPACE" exec "$AGENT_POD" -- \
  curl -s -v -k --max-time 5 "https://not-allowed.example.com/" 2>&1) || true
if echo "$CONNECT_OUTPUT" | grep -q "HTTP/1.1 403"; then
  pass "CONNECT tunnel rejected with 403"
else
  fail "CONNECT rejection not detected"
  echo "  Output: $(echo "$CONNECT_OUTPUT" | grep -i "HTTP/" | head -3)"
fi

# ========================================
# Infrastructure health
# ========================================

info "Test 13: Warden pod health (liveness + readiness probes)"
WARDEN_POD=$(kubectl -n "$NAMESPACE" get pods -l app=warden -o jsonpath='{.items[0].metadata.name}')
WARDEN_READY=$(kubectl -n "$NAMESPACE" get pod "$WARDEN_POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
WARDEN_RESTARTS=$(kubectl -n "$NAMESPACE" get pod "$WARDEN_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')
if [ "$WARDEN_READY" = "True" ] && [ "$WARDEN_RESTARTS" = "0" ]; then
  pass "Ready=True, restarts=$WARDEN_RESTARTS"
else
  fail "Ready=$WARDEN_READY, restarts=$WARDEN_RESTARTS"
fi

# ========================================
# Agent Sandbox CRD lifecycle
# ========================================

info "Test 14: Sandbox CRD created agent pod"
POD_READY=$(kubectl -n "$NAMESPACE" get pod test-agent -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || true
if [ "$POD_READY" = "True" ]; then pass "Sandbox pod test-agent Ready=True"
else fail "Sandbox pod test-agent Ready=$POD_READY"; fi

info "Test 15: SandboxClaim created pod from SandboxTemplate"
CLAIM_SANDBOX=$(kubectl -n "$NAMESPACE" get sandboxclaim dev-agent -o jsonpath='{.status.sandboxName}' 2>/dev/null) || true
if [ -n "$CLAIM_SANDBOX" ]; then
  CLAIM_POD_READY=$(kubectl -n "$NAMESPACE" get pod "$CLAIM_SANDBOX" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || true
  if [ "$CLAIM_POD_READY" = "True" ]; then pass "SandboxClaim → $CLAIM_SANDBOX Ready=True"
  else pass "SandboxClaim → $CLAIM_SANDBOX created"; fi
else
  DEV_POD_READY=$(kubectl -n "$NAMESPACE" get pod dev-agent -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) || true
  if [ "$DEV_POD_READY" = "True" ]; then pass "SandboxClaim pod dev-agent Ready=True"
  else fail "SandboxClaim: no sandbox or pod found"; fi
fi

# ========================================
# NetworkPolicy enforcement
# ========================================

info "Test 16: Direct connection bypassing proxy (blocked by NetworkPolicy)"
DIRECT_CODE=$(kubectl -n "$NAMESPACE" exec "$AGENT_POD" -- \
  curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  --noproxy '*' "http://test-server.agent-sandbox.svc/get" 2>/dev/null) || true
if [ "${DIRECT_CODE:-}" = "000" ] || [ -z "${DIRECT_CODE:-}" ]; then
  pass "direct connection blocked"
else
  fail "direct connection returned $DIRECT_CODE (expected timeout)"
fi

# ---- Summary ----
echo ""
info "============================================"
info "  Results: $PASS passed, $FAIL failed"
info "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  info "Debug:"
  info "  Warden logs:      kubectl -n $NAMESPACE logs -l app=warden"
  info "  Test server logs:  kubectl -n $NAMESPACE logs -l app=test-server"
  info "  Agent exec:        kubectl -n $NAMESPACE exec -it $AGENT_POD -- sh"
  exit 1
fi
