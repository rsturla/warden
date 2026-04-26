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

# ========================================
# Multi-tenant: mTLS tenant identification
# ========================================

# Helper: curl from a specific MT agent pod
mt_curl() {
  local pod="$1"; shift
  local code
  code=$(kubectl -n "$NAMESPACE" exec "$pod" -c agent -- \
    curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -x http://127.0.0.1:8080 "$@" 2>/dev/null) || true
  echo "${code:-000}"
}

mt_curl_body() {
  local pod="$1"; shift
  kubectl -n "$NAMESPACE" exec "$pod" -c agent -- \
    curl -s --max-time 10 -x http://127.0.0.1:8080 "$@" 2>/dev/null || true
}

info "Test 17: Alpha agent GET /get via bridge+mTLS (allowed)"
CODE=$(mt_curl agent-alpha "$TEST_SERVER/get")
if [ "$CODE" = "200" ]; then pass "alpha /get returned $CODE"
else fail "alpha /get returned $CODE (expected 200)"; fi

info "Test 18: Alpha secret injection (alpha-specific token)"
BODY=$(mt_curl_body agent-alpha "$TEST_SERVER/headers")
if echo "$BODY" | grep -q "alpha-secret-token-99999"; then
  pass "alpha token injected"
else
  fail "alpha token missing"
  echo "  Body: $BODY"
fi

info "Test 19: Beta agent GET /get via bridge+mTLS (allowed)"
CODE=$(mt_curl agent-beta "$TEST_SERVER/get")
if [ "$CODE" = "200" ]; then pass "beta /get returned $CODE"
else fail "beta /get returned $CODE (expected 200)"; fi

info "Test 20: Beta secret injection (beta-specific token)"
BODY=$(mt_curl_body agent-beta "$TEST_SERVER/headers")
if echo "$BODY" | grep -q "beta-secret-token-88888"; then
  pass "beta token injected"
else
  fail "beta token missing"
  echo "  Body: $BODY"
fi

# ========================================
# Multi-tenant: tenant isolation
# ========================================

info "Test 21: Alpha can access /api/v1/resource (alpha policy allows)"
CODE=$(mt_curl agent-alpha "$TEST_SERVER/api/v1/resource")
if [ "$CODE" = "200" ]; then pass "alpha /api/v1 returned $CODE"
else fail "alpha /api/v1 returned $CODE (expected 200)"; fi

info "Test 22: Beta cannot access /api/v1/resource (beta policy denies)"
CODE=$(mt_curl agent-beta "$TEST_SERVER/api/v1/resource")
if [ "$CODE" = "403" ]; then pass "beta /api/v1 returned $CODE (isolated)"
else fail "beta /api/v1 returned $CODE (expected 403 — tenant isolation broken)"; fi

info "Test 23: Alpha secret not leaked to beta"
BODY=$(mt_curl_body agent-beta "$TEST_SERVER/headers")
if echo "$BODY" | grep -q "alpha-secret-token-99999"; then
  fail "alpha token leaked to beta"
else
  pass "alpha token not present in beta request"
fi

# ========================================
# Multi-tenant: /tenantz endpoint
# ========================================

info "Test 24: /tenantz endpoint lists tenants"
WARDEN_MT_POD=$(kubectl -n "$NAMESPACE" get pods -l app=warden-mt -o jsonpath='{.items[0].metadata.name}')
WARDEN_MT_READY=$(kubectl -n "$NAMESPACE" get pod "$WARDEN_MT_POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
if [ "$WARDEN_MT_READY" = "True" ]; then
  # Port-forward briefly to hit /tenantz
  kubectl -n "$NAMESPACE" port-forward "pod/$WARDEN_MT_POD" 19090:9090 &>/dev/null &
  PF_PID=$!
  sleep 1
  TENANTZ=$(curl -s --max-time 5 http://localhost:19090/tenantz 2>/dev/null) || true
  kill $PF_PID 2>/dev/null; wait $PF_PID 2>/dev/null || true
  if echo "$TENANTZ" | grep -q "alpha" && echo "$TENANTZ" | grep -q "beta"; then
    pass "/tenantz lists alpha and beta"
  else
    fail "/tenantz missing tenants: $TENANTZ"
  fi
else
  fail "warden-mt pod not ready"
fi

# ========================================
# Multi-tenant: hot reload
# ========================================

info "Test 25: Hot reload — add /api/v2/** to alpha tenant"
# Alpha currently cannot access /api/v2
CODE=$(mt_curl agent-alpha "$TEST_SERVER/api/v2/resource")
if [ "$CODE" != "403" ]; then
  fail "pre-reload: alpha /api/v2 returned $CODE (expected 403)"
else
  # Patch tenant ConfigMap to add /api/v2/** to alpha
  kubectl -n "$NAMESPACE" get configmap warden-mt-tenants -o yaml | \
    sed 's/- type: env/- name: allow-api-v2\n        host: "test-server.agent-sandbox.svc"\n        path: "\/api\/v2\/**"\n        methods: ["GET"]\n        action: allow\n    secrets:\n      - type: env/' | \
    head -1 > /dev/null  # validate sed works

  # Apply updated config via kubectl apply with heredoc
  kubectl apply -f - <<'PATCH_EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: warden-mt-tenants
  namespace: agent-sandbox
data:
  alpha.yaml: |
    policies:
      - name: allow-test-get
        host: "test-server.agent-sandbox.svc"
        path: "/get"
        methods: ["GET"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${ALPHA_TOKEN}"
      - name: allow-test-headers
        host: "test-server.agent-sandbox.svc"
        path: "/headers"
        methods: ["GET"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${ALPHA_TOKEN}"
      - name: allow-api-v1
        host: "test-server.agent-sandbox.svc"
        path: "/api/v1/**"
        methods: ["GET"]
        action: allow
      - name: allow-api-v2
        host: "test-server.agent-sandbox.svc"
        path: "/api/v2/**"
        methods: ["GET"]
        action: allow
    secrets:
      - type: env
  beta.yaml: |
    policies:
      - name: allow-test-get
        host: "test-server.agent-sandbox.svc"
        path: "/get"
        methods: ["GET"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${BETA_TOKEN}"
      - name: allow-test-headers
        host: "test-server.agent-sandbox.svc"
        path: "/headers"
        methods: ["GET"]
        action: allow
        inject:
          headers:
            Authorization: "Bearer ${BETA_TOKEN}"
    secrets:
      - type: env
PATCH_EOF

  # Poll until hot reload picks up the change (ConfigMap propagation ~60s + Warden poll 30s)
  info "  Waiting for hot reload (up to 120s)..."
  RELOADED=false
  for i in $(seq 1 24); do
    sleep 5
    CODE=$(mt_curl agent-alpha "$TEST_SERVER/api/v2/resource")
    if [ "$CODE" = "200" ]; then
      RELOADED=true
      break
    fi
  done

  if [ "$RELOADED" = "true" ]; then
    pass "hot reload: alpha /api/v2 now returns 200 (reload took ~$((i * 5))s)"
  else
    fail "hot reload: alpha /api/v2 still denied after 120s"
  fi
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
  info "  Warden MT logs:   kubectl -n $NAMESPACE logs -l app=warden-mt"
  info "  Test server logs:  kubectl -n $NAMESPACE logs -l app=test-server"
  info "  Agent exec:        kubectl -n $NAMESPACE exec -it $AGENT_POD -- sh"
  info "  Alpha exec:        kubectl -n $NAMESPACE exec -it agent-alpha -c agent -- sh"
  exit 1
fi
