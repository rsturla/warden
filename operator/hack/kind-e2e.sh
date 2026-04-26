#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$OPERATOR_DIR/.." && pwd)"
CLUSTER_NAME="warden-operator-e2e"
NAMESPACE="test-warden"
OP_NAMESPACE="warden-operator-system"

info()  { echo "==> $*"; }
error() { echo "ERROR: $*" >&2; exit 1; }

for cmd in kind kubectl docker; do
  command -v "$cmd" >/dev/null || error "$cmd not found"
done

# Cluster
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  info "Cluster exists, reusing"
else
  info "Creating kind cluster"
  kind create cluster --name "$CLUSTER_NAME"
fi
kubectl config use-context "kind-${CLUSTER_NAME}"

# Build images
info "Building Warden image"
docker build -t warden:latest -f "$REPO_ROOT/Containerfile" "$REPO_ROOT"

info "Building operator image"
docker build -t warden-operator:latest -f "$OPERATOR_DIR/Containerfile" "$REPO_ROOT"

info "Building test server image"
docker build -t test-server:latest -f "$REPO_ROOT/hack/kind/testserver/Containerfile" "$REPO_ROOT/hack/kind/testserver"

info "Loading images into kind"
kind load docker-image warden:latest warden-operator:latest test-server:latest --name "$CLUSTER_NAME"

# Install cert-manager
if ! kubectl get namespace cert-manager &>/dev/null; then
  info "Installing cert-manager"
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.2/cert-manager.yaml
  kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=180s
  kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=180s
fi

# Install CRDs
info "Installing CRDs"
kubectl apply -f "$OPERATOR_DIR/config/crd/bases/"

# Deploy operator with webhook
info "Deploying operator"
kubectl create namespace "$OP_NAMESPACE" 2>/dev/null || true

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: warden-operator
  namespace: $OP_NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: warden-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: warden-operator
    namespace: $OP_NAMESPACE
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: webhook-selfsigned
  namespace: $OP_NAMESPACE
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: webhook-cert
  namespace: $OP_NAMESPACE
spec:
  secretName: warden-operator-webhook-tls
  dnsNames:
    - warden-operator-webhook.$OP_NAMESPACE.svc
    - warden-operator-webhook.$OP_NAMESPACE.svc.cluster.local
  issuerRef:
    name: webhook-selfsigned
  privateKey:
    algorithm: ECDSA
    size: 256
---
apiVersion: v1
kind: Service
metadata:
  name: warden-operator-webhook
  namespace: $OP_NAMESPACE
spec:
  selector:
    app: warden-operator
  ports:
    - port: 443
      targetPort: 9443
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: warden-operator
  namespace: $OP_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: warden-operator
  template:
    metadata:
      labels:
        app: warden-operator
    spec:
      serviceAccountName: warden-operator
      containers:
        - name: operator
          image: warden-operator:latest
          imagePullPolicy: Never
          args:
            - "--health-probe-bind-address=:8081"
            - "--webhook-port=9443"
          ports:
            - containerPort: 9443
              name: webhook
            - containerPort: 8081
              name: health
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8081
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8081
          volumeMounts:
            - name: webhook-certs
              mountPath: /tmp/k8s-webhook-server/serving-certs
              readOnly: true
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
      volumes:
        - name: webhook-certs
          secret:
            secretName: warden-operator-webhook-tls
EOF

# Wait for webhook cert to be issued
info "Waiting for webhook certificate"
kubectl wait --for=condition=Ready certificate webhook-cert \
  -n "$OP_NAMESPACE" --timeout=60s

info "Waiting for operator"
kubectl wait --for=condition=Ready pods -l app=warden-operator \
  -n "$OP_NAMESPACE" --timeout=120s

# Get CA bundle for webhook config
CA_BUNDLE=$(kubectl -n "$OP_NAMESPACE" get secret warden-operator-webhook-tls \
  -o jsonpath='{.data.ca\.crt}')

# Create MutatingWebhookConfiguration
kubectl apply -f - <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: warden-operator
webhooks:
  - name: pod-mutator.wardenproxy.dev
    admissionReviewVersions: ["v1"]
    sideEffects: None
    clientConfig:
      service:
        name: warden-operator-webhook
        namespace: $OP_NAMESPACE
        path: /mutate-v1-pod
      caBundle: $CA_BUNDLE
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
    failurePolicy: Ignore
    namespaceSelector:
      matchLabels:
        wardenproxy.dev/inject: "enabled"
EOF

# Create test namespace
info "Creating test namespace"
kubectl create namespace "$NAMESPACE" 2>/dev/null || true
kubectl label namespace "$NAMESPACE" wardenproxy.dev/inject=enabled --overwrite

# Deploy test server
kubectl apply -n "$NAMESPACE" -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-server
  template:
    metadata:
      labels:
        app: test-server
    spec:
      containers:
        - name: test-server
          image: test-server:latest
          imagePullPolicy: Never
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: test-server
spec:
  selector:
    app: test-server
  ports:
    - port: 80
      targetPort: 8080
EOF
kubectl wait --for=condition=Ready pods -l app=test-server \
  -n "$NAMESPACE" --timeout=60s

# Create WardenProxy CR
kubectl apply -n "$NAMESPACE" -f - <<'EOF'
apiVersion: wardenproxy.dev/v1alpha1
kind: WardenProxy
metadata:
  name: warden
spec:
  image: warden:latest
  multiTenant:
    certificateIssuerRef:
      name: tenant-ca-issuer
      kind: Issuer
  dns:
    cache:
      enabled: true
    denyResolvedIPs:
      - "169.254.0.0/16"
  telemetry:
    logs:
      level: debug
      format: json
EOF

sleep 3

# ---- Tests ----
PASS=0
FAIL=0
pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

info "Test 1: WardenProxy created Deployment"
if kubectl -n "$NAMESPACE" get deployment warden &>/dev/null; then
  pass "Deployment 'warden' exists"
else fail "Deployment not found"; fi

info "Test 2: WardenProxy created Service"
if kubectl -n "$NAMESPACE" get service warden &>/dev/null; then
  pass "Service 'warden' exists"
else fail "Service not found"; fi

info "Test 3: WardenProxy created ConfigMap"
CM_DATA=$(kubectl -n "$NAMESPACE" get configmap warden-config -o jsonpath='{.data.config\.yaml}' 2>/dev/null) || true
if [ -n "$CM_DATA" ]; then pass "ConfigMap has config.yaml"
else fail "ConfigMap missing"; fi

info "Test 4: WardenProxy status Ready"
READY=$(kubectl -n "$NAMESPACE" get wardenproxy warden -o jsonpath='{.status.ready}' 2>/dev/null) || true
if [ "$READY" = "true" ]; then pass "status.ready=true"
else fail "status.ready=$READY"; fi

# Create Tenant
info "Test 5: Create Tenant CR"
kubectl apply -n "$NAMESPACE" -f - <<'EOF'
apiVersion: wardenproxy.dev/v1alpha1
kind: Tenant
metadata:
  name: alpha
spec:
  policies:
    - name: allow-test
      host: "test-server.test-warden.svc"
      path: "/get"
      methods: ["GET"]
      action: allow
  secrets:
    - type: env
EOF
sleep 5

info "Test 6: Tenant config in ConfigMap"
TENANT_KEY=$(kubectl -n "$NAMESPACE" get configmap warden-tenants -o jsonpath='{.data.alpha\.yaml}' 2>/dev/null) || true
if [ -n "$TENANT_KEY" ]; then pass "alpha.yaml in ConfigMap"
else fail "alpha.yaml missing"; fi

info "Test 7: Tenant status Ready"
T_READY=$(kubectl -n "$NAMESPACE" get tenant alpha -o jsonpath='{.status.ready}' 2>/dev/null) || true
if [ "$T_READY" = "true" ]; then pass "tenant status.ready=true"
else fail "tenant status.ready=$T_READY"; fi

# Webhook injection test
info "Test 8: Webhook injects bridge sidecar"
kubectl run -n "$NAMESPACE" webhook-test --image=curlimages/curl:latest \
  --labels="wardenproxy.dev/inject=true,wardenproxy.dev/tenant=alpha" \
  --command -- sleep infinity 2>/dev/null || true
sleep 3

CONTAINERS=$(kubectl -n "$NAMESPACE" get pod webhook-test -o jsonpath='{.spec.containers[*].name}' 2>/dev/null) || true
if echo "$CONTAINERS" | grep -q "warden-bridge"; then
  pass "warden-bridge sidecar injected"
else
  fail "warden-bridge not found in containers: $CONTAINERS"
fi

info "Test 9: Webhook sets HTTP_PROXY env"
HTTP_PROXY=$(kubectl -n "$NAMESPACE" get pod webhook-test \
  -o jsonpath='{.spec.containers[0].env[?(@.name=="HTTP_PROXY")].value}' 2>/dev/null) || true
if [ "$HTTP_PROXY" = "http://127.0.0.1:8080" ]; then
  pass "HTTP_PROXY=http://127.0.0.1:8080"
else
  fail "HTTP_PROXY=$HTTP_PROXY"
fi

info "Test 10: Webhook adds role=agent label"
ROLE=$(kubectl -n "$NAMESPACE" get pod webhook-test -o jsonpath='{.metadata.labels.role}' 2>/dev/null) || true
if [ "$ROLE" = "agent" ]; then pass "role=agent label set"
else fail "role=$ROLE"; fi

# Tenant deletion
info "Test 11: Tenant deletion removes ConfigMap entry"
kubectl -n "$NAMESPACE" delete tenant alpha --wait=true --timeout=30s 2>/dev/null || true
sleep 3
AFTER=$(kubectl -n "$NAMESPACE" get configmap warden-tenants -o jsonpath='{.data.alpha\.yaml}' 2>/dev/null) || true
if [ -z "$AFTER" ]; then pass "alpha.yaml removed after deletion"
else fail "alpha.yaml still present"; fi

# Summary
echo ""
info "============================================"
info "  Results: $PASS passed, $FAIL failed"
info "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  info "Debug:"
  info "  Operator logs: kubectl -n $OP_NAMESPACE logs -l app=warden-operator"
  info "  Resources:     kubectl -n $NAMESPACE get all"
  exit 1
fi
