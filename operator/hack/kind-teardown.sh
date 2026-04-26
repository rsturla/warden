#!/usr/bin/env bash
set -euo pipefail

echo "==> Deleting kind cluster 'warden-operator-e2e'"
kind delete cluster --name warden-operator-e2e
echo "==> Done"
