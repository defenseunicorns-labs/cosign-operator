#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFESTS="$SCRIPT_DIR/manifests"
REGISTRY="localhost:5050"
IMAGE_NAME="e2e-app"
FULL_IMAGE="$REGISTRY/$IMAGE_NAME:latest"
COSIGN_KEY="$ROOT/cosign.key"

NAMESPACES=(
  e2e-no-policy
  e2e-sig-enforce
  e2e-sig-warn
  e2e-sbom-mutate
  e2e-sbom-deny
  e2e-unsigned-reject
  e2e-unsigned-warn
  e2e-skip
  e2e-dup
)

echo "==> Starting local registry on port 5050..."
docker rm -f e2e-registry 2>/dev/null || true
docker run -d --name e2e-registry -p 5050:5000 registry:2
until curl -sf http://localhost:5050/v2/ >/dev/null 2>&1; do sleep 1; done

echo "==> Building and pushing test image..."
docker build -t "$FULL_IMAGE" "$ROOT"
docker push "$FULL_IMAGE"

echo "==> Getting digest..."
DIGEST=$(crane digest "$FULL_IMAGE")
DIGEST_HEX="${DIGEST#sha256:}"
IMAGE_REF="$REGISTRY/$IMAGE_NAME@$DIGEST"
IMAGE_SIG="$REGISTRY/$IMAGE_NAME:sha256-${DIGEST_HEX}.sig"
IMAGE_SBOM="$REGISTRY/$IMAGE_NAME:sha256-${DIGEST_HEX}.sbom"

echo "==> Signing image..."
COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY" \
  --new-bundle-format=false --use-signing-config=false --tlog-upload=false \
  "$IMAGE_REF" 2>/dev/null \
|| COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY" \
  --tlog-upload=false \
  "$IMAGE_REF" 2>/dev/null \
|| COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY" \
  "$IMAGE_REF"

echo "==> Generating SBOM..."
syft scan "$IMAGE_REF" -o spdx-json="$SCRIPT_DIR/sbom.spdx.json"

echo "==> Attaching SBOM as .sbom tag..."
cosign upload blob -f "$SCRIPT_DIR/sbom.spdx.json" \
  "$REGISTRY/$IMAGE_NAME:sha256-${DIGEST_HEX}.sbom"

echo "==> Generating signed-app zarf.yaml from template..."
export IMAGE_REF IMAGE_SIG IMAGE_SBOM
envsubst < "$MANIFESTS/signed-app/zarf.yaml.tmpl" > "$MANIFESTS/signed-app/zarf.yaml"

echo "==> Creating Zarf packages..."
zarf package create "$MANIFESTS/signed-app"  -o "$SCRIPT_DIR" --confirm --skip-sbom
zarf package create "$MANIFESTS/unsigned-app" -o "$SCRIPT_DIR" --confirm --skip-sbom
zarf package create "$MANIFESTS/skip-app"    -o "$SCRIPT_DIR" --confirm --skip-sbom

echo "==> Creating test namespaces..."
for ns in "${NAMESPACES[@]}"; do
  kubectl create namespace "$ns" 2>/dev/null || true
done

echo "==> Deploying seed apps via Zarf (no policies yet — seeds registry)..."
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-signed-app-*.tar.zst --confirm --set NAMESPACE=e2e-no-policy
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-unsigned-app-*.tar.zst --confirm --set NAMESPACE=e2e-unsigned-warn
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-skip-app-*.tar.zst --confirm --set NAMESPACE=e2e-skip

echo "==> Resolving Zarf image refs for kubectl manifests..."
SIGNED_IMAGE=$(kubectl get pod -n e2e-no-policy -l app=e2e-signed-app -o jsonpath='{.items[0].spec.containers[0].image}')
UNSIGNED_IMAGE=$(kubectl get pod -n e2e-unsigned-warn -l app=e2e-unsigned-app -o jsonpath='{.items[0].spec.containers[0].image}')
echo "    Signed image:   $SIGNED_IMAGE"
echo "    Unsigned image:  $UNSIGNED_IMAGE"

RESOLVED="$SCRIPT_DIR/resolved"
mkdir -p "$RESOLVED"
for ns in "${NAMESPACES[@]}"; do
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|###ZARF_CONST_IMAGE###|$SIGNED_IMAGE|" \
    "$MANIFESTS/signed-app/deployment.yaml" > "$RESOLVED/signed-app-$ns.yaml"
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|docker.io/library/nginx:1.27-alpine|$UNSIGNED_IMAGE|" \
    "$MANIFESTS/unsigned-app/deployment.yaml" > "$RESOLVED/unsigned-app-$ns.yaml"
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|docker.io/library/nginx:1.27-alpine|$UNSIGNED_IMAGE|" \
    "$MANIFESTS/skip-app/deployment.yaml" > "$RESOLVED/skip-app-$ns.yaml"
done

echo "==> Applying CRD instances..."
kubectl apply -f "$MANIFESTS/crs/"

echo "==> Waiting for CRD statuses..."
for cr in sig-enforce-test sig-reject-test sig-warn-test sig-skip-test sig-dup-first; do
  kubectl wait --for=jsonpath='{.status.conditions[0].status}'=True \
    signatureenforcement/"$cr" --timeout=30s 2>/dev/null || true
done
for cr in sbom-mutate-test sbom-deny-test sbom-dup-first; do
  kubectl wait --for=jsonpath='{.status.conditions[0].status}'=True \
    sbomenforcement/"$cr" --timeout=30s 2>/dev/null || true
done

echo "==> Deploying signed app to enforced namespaces via kubectl..."
kubectl apply -f "$RESOLVED/signed-app-e2e-sig-enforce.yaml"
kubectl apply -f "$RESOLVED/signed-app-e2e-sbom-mutate.yaml"
kubectl rollout status deployment/e2e-signed-app -n e2e-sig-enforce --timeout=60s
kubectl rollout status deployment/e2e-signed-app -n e2e-sbom-mutate --timeout=60s

echo "==> Setup complete. Run: make test-e2e"
