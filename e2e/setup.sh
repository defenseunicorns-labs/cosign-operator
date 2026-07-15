#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFESTS="$SCRIPT_DIR/manifests"
REGISTRY="localhost:5050"
IMAGE_NAME="e2e-app"
FULL_IMAGE="$REGISTRY/$IMAGE_NAME:latest"
COSIGN_KEY="$ROOT/cosign.key"

# A second app signed with a SECOND, independent cosign key. Its public key is
# uploaded as a labeled Secret so the operator trusts it alongside the base key.
IMAGE_NAME2="e2e-app-2"
FULL_IMAGE2="$REGISTRY/$IMAGE_NAME2:latest"
COSIGN_KEY2="$ROOT/cosign2.key"
COSIGN_PUB2="$ROOT/cosign2.pub"

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
  e2e-sig-multikey
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

echo "==> Generating second cosign key pair..."
test -f "$COSIGN_KEY2" || COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$ROOT/cosign2"

echo "==> Building and pushing second test image (distinct digest)..."
# The --label gives this image a different config — and therefore a different
# digest — so it is genuinely a separate artifact signed only by the second key.
docker build -t "$FULL_IMAGE2" --label e2e.variant=key2 "$ROOT"
docker push "$FULL_IMAGE2"

echo "==> Getting second image digest..."
DIGEST2=$(crane digest "$FULL_IMAGE2")
DIGEST2_HEX="${DIGEST2#sha256:}"
IMAGE_REF2="$REGISTRY/$IMAGE_NAME2@$DIGEST2"
IMAGE_SIG2="$REGISTRY/$IMAGE_NAME2:sha256-${DIGEST2_HEX}.sig"
IMAGE_SBOM2="$REGISTRY/$IMAGE_NAME2:sha256-${DIGEST2_HEX}.sbom"

echo "==> Signing second image with the SECOND key..."
COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY2" \
  --new-bundle-format=false --use-signing-config=false --tlog-upload=false \
  "$IMAGE_REF2" 2>/dev/null \
|| COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY2" \
  --tlog-upload=false \
  "$IMAGE_REF2" 2>/dev/null \
|| COSIGN_PASSWORD="" cosign sign --key "$COSIGN_KEY2" \
  "$IMAGE_REF2"

echo "==> Generating SBOM for second image..."
syft scan "$IMAGE_REF2" -o spdx-json="$SCRIPT_DIR/sbom2.spdx.json"
cosign upload blob -f "$SCRIPT_DIR/sbom2.spdx.json" \
  "$REGISTRY/$IMAGE_NAME2:sha256-${DIGEST2_HEX}.sbom"

echo "==> Generating signed-app zarf.yaml from template..."
export IMAGE_REF IMAGE_SIG IMAGE_SBOM
envsubst < "$MANIFESTS/signed-app/zarf.yaml.tmpl" > "$MANIFESTS/signed-app/zarf.yaml"

echo "==> Generating signed-app-2 zarf.yaml from template..."
export IMAGE_REF2 IMAGE_SIG2 IMAGE_SBOM2
envsubst < "$MANIFESTS/signed-app-2/zarf.yaml.tmpl" > "$MANIFESTS/signed-app-2/zarf.yaml"

echo "==> Creating Zarf packages..."
zarf package create "$MANIFESTS/signed-app"   -o "$SCRIPT_DIR" --confirm --skip-sbom
zarf package create "$MANIFESTS/signed-app-2" -o "$SCRIPT_DIR" --confirm --skip-sbom
zarf package create "$MANIFESTS/unsigned-app" -o "$SCRIPT_DIR" --confirm --skip-sbom
zarf package create "$MANIFESTS/skip-app"     -o "$SCRIPT_DIR" --confirm --skip-sbom

echo "==> Creating test namespaces..."
for ns in "${NAMESPACES[@]}"; do
  kubectl create namespace "$ns" 2>/dev/null || true
done

echo "==> Uploading the second public key as a trusted, labeled Secret..."
# The operator's publicKeyWatch picks up every Secret in pepr-system labeled
# pepr.dev/secret-type=cosign-public-key and adds its key(s) to the trusted set.
kubectl create secret generic cosign-public-key-2 \
  --namespace pepr-system \
  --from-file=cosign.pub="$COSIGN_PUB2" \
  --dry-run=client -o yaml \
  | kubectl label --local -f - pepr.dev/secret-type=cosign-public-key -o yaml \
  | kubectl apply -f -

echo "==> Deploying seed apps via Zarf (no policies yet — seeds registry)..."
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-signed-app-amd64-*.tar.zst --confirm --set NAMESPACE=e2e-no-policy
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-signed-app-2-*.tar.zst --confirm --set NAMESPACE=e2e-no-policy
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-unsigned-app-*.tar.zst --confirm --set NAMESPACE=e2e-unsigned-warn
zarf package deploy "$SCRIPT_DIR"/zarf-package-e2e-skip-app-*.tar.zst --confirm --set NAMESPACE=e2e-skip

# The kubectl-applied deployments (e2e-sig-enforce, e2e-sbom-mutate, etc.) get
# their image rewritten to the Zarf internal registry by the Zarf agent, which
# also injects an imagePullSecrets: [private-registry] reference. Unlike the
# Zarf-deployed seed apps, that secret is never created in these namespaces, so
# the authenticated pull fails with "no basic auth credentials" on any node that
# doesn't already have the layer cached (i.e. anything past a single node).
# Copy the secret from a namespace Zarf already populated into every test ns.
echo "==> Copying Zarf registry pull secret into test namespaces..."
DOCKERCFG=$(kubectl get secret private-registry -n e2e-no-policy -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d)
for ns in "${NAMESPACES[@]}"; do
  kubectl create secret generic private-registry \
    --type=kubernetes.io/dockerconfigjson \
    --from-literal=.dockerconfigjson="$DOCKERCFG" \
    -n "$ns" --dry-run=client -o yaml | kubectl apply -f -
done

echo "==> Resolving Zarf image refs for kubectl manifests..."
SIGNED_IMAGE=$(kubectl get pod -n e2e-no-policy -l app=e2e-signed-app -o jsonpath='{.items[0].spec.containers[0].image}')
SIGNED_IMAGE2=$(kubectl get pod -n e2e-no-policy -l app=e2e-signed-app-2 -o jsonpath='{.items[0].spec.containers[0].image}')
UNSIGNED_IMAGE=$(kubectl get pod -n e2e-unsigned-warn -l app=e2e-unsigned-app -o jsonpath='{.items[0].spec.containers[0].image}')
echo "    Signed image:    $SIGNED_IMAGE"
echo "    Signed image 2:  $SIGNED_IMAGE2"
echo "    Unsigned image:  $UNSIGNED_IMAGE"

RESOLVED="$SCRIPT_DIR/resolved"
mkdir -p "$RESOLVED"
for ns in "${NAMESPACES[@]}"; do
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|###ZARF_CONST_IMAGE###|$SIGNED_IMAGE|" \
    "$MANIFESTS/signed-app/deployment.yaml" > "$RESOLVED/signed-app-$ns.yaml"
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|###ZARF_CONST_IMAGE###|$SIGNED_IMAGE2|" \
    "$MANIFESTS/signed-app-2/deployment.yaml" > "$RESOLVED/signed-app-2-$ns.yaml"
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|docker.io/library/nginx:1.27-alpine|$UNSIGNED_IMAGE|" \
    "$MANIFESTS/unsigned-app/deployment.yaml" > "$RESOLVED/unsigned-app-$ns.yaml"
  sed "s|###ZARF_VAR_NAMESPACE###|$ns|;s|docker.io/library/nginx:1.27-alpine|$UNSIGNED_IMAGE|" \
    "$MANIFESTS/skip-app/deployment.yaml" > "$RESOLVED/skip-app-$ns.yaml"
done

echo "==> Applying CRD instances..."
kubectl apply -f "$MANIFESTS/crs/"

echo "==> Waiting for CRD statuses..."
for cr in sig-enforce-test sig-reject-test sig-warn-test sig-skip-test sig-dup-first sig-multikey-test; do
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
kubectl rollout status deployment/e2e-signed-app -n e2e-sig-enforce --timeout=360s
kubectl rollout status deployment/e2e-signed-app -n e2e-sbom-mutate --timeout=360s

echo "==> Deploying second-key signed app to its enforced namespace via kubectl..."
# Admission must trust the second key (uploaded above) for this to be admitted.
kubectl apply -f "$RESOLVED/signed-app-2-e2e-sig-multikey.yaml"
kubectl rollout status deployment/e2e-signed-app-2 -n e2e-sig-multikey --timeout=360s

echo "==> Setup complete. Run: uds run test-e2e"
