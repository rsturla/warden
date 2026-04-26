#!/usr/bin/env bash
set -euo pipefail

# Generate all TLS certificates for multi-tenant e2e testing.
# Output: K8s secrets created in agent-sandbox namespace.

NAMESPACE="agent-sandbox"
CERT_DIR=$(mktemp -d)
trap 'rm -rf "$CERT_DIR"' EXIT

info() { echo "==> $*"; }

# Tenant CA — signs client certificates
info "Generating tenant CA"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/tenant-ca.key" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/tenant-ca.key" -out "$CERT_DIR/tenant-ca.crt" \
  -days 1 -subj "/CN=Warden Tenant CA" 2>/dev/null

# MITM CA — for HTTPS interception
info "Generating MITM CA"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/mitm-ca.key" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/mitm-ca.key" -out "$CERT_DIR/mitm-ca.crt" \
  -days 1 -subj "/CN=Warden MITM CA" 2>/dev/null

# Server certificate for multi-tenant Warden (signed by tenant CA)
info "Generating server certificate"
openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/server.key" 2>/dev/null
cat > "$CERT_DIR/server.ext" <<EOX
[req]
distinguished_name = req_dn
req_extensions = v3_req
[req_dn]
CN = warden-mt
[v3_req]
subjectAltName = DNS:warden-mt,DNS:warden-mt.agent-sandbox.svc,DNS:warden-mt.agent-sandbox.svc.cluster.local
EOX
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=warden-mt" -config "$CERT_DIR/server.ext" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/tenant-ca.crt" -CAkey "$CERT_DIR/tenant-ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 1 \
  -extfile "$CERT_DIR/server.ext" -extensions v3_req 2>/dev/null

# Client certificates (CN = tenant ID)
for TENANT in alpha beta; do
  info "Generating client certificate for tenant: $TENANT"
  openssl ecparam -genkey -name prime256v1 -noout -out "$CERT_DIR/$TENANT.key" 2>/dev/null
  openssl req -new -key "$CERT_DIR/$TENANT.key" -out "$CERT_DIR/$TENANT.csr" \
    -subj "/CN=$TENANT" 2>/dev/null
  openssl x509 -req -in "$CERT_DIR/$TENANT.csr" \
    -CA "$CERT_DIR/tenant-ca.crt" -CAkey "$CERT_DIR/tenant-ca.key" -CAcreateserial \
    -out "$CERT_DIR/$TENANT.crt" -days 1 2>/dev/null
done

# Create K8s secrets
info "Creating K8s secrets"

kubectl -n "$NAMESPACE" create secret tls warden-mt-server-tls \
  --cert="$CERT_DIR/server.crt" --key="$CERT_DIR/server.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic warden-mt-tenant-ca \
  --from-file=ca.crt="$CERT_DIR/tenant-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic warden-mt-mitm-ca \
  --from-file=ca.crt="$CERT_DIR/mitm-ca.crt" \
  --from-file=ca.key="$CERT_DIR/mitm-ca.key" \
  --dry-run=client -o yaml | kubectl apply -f -

for TENANT in alpha beta; do
  kubectl -n "$NAMESPACE" create secret generic "agent-${TENANT}-cert" \
    --from-file=tls.crt="$CERT_DIR/$TENANT.crt" \
    --from-file=tls.key="$CERT_DIR/$TENANT.key" \
    --from-file=ca.crt="$CERT_DIR/tenant-ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f -
done

info "Certificates created"
