# Image Signature & SBOM Policy

A [Pepr](https://pepr.dev) admission controller that enforces cosign image signatures and SBOM component policies via Kubernetes CRDs. Packaged and deployed as a [UDS](https://github.com/defenseunicorns/uds-cli) bundle.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Node.js](https://nodejs.org/)
- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane), [syft](https://github.com/anchore/syft)
- [k3d](https://k3d.io/), [Zarf](https://docs.zarf.dev/getting-started/), [UDS CLI](https://github.com/defenseunicorns/uds-cli)

## Quick Start

```bash
# Generate cosign keys (if you don't have them)
COSIGN_PASSWORD="" cosign generate-key-pair

# Build the Pepr policy and Zarf package
make build-policy
zarf package create . --confirm --skip-sbom

# Create the UDS bundle
cd bundle && uds create --confirm && cd ..

# Create a cluster and deploy
k3d cluster create
uds deploy bundle/uds-bundle-image-signature-policy-amd64-0.0.1.tar.zst --confirm
```

## CRDs

### SignatureEnforcement

Enforces cosign image signature verification for pods in specified namespaces.

```yaml
apiVersion: policy.uds.dev/v1alpha1
kind: SignatureEnforcement
metadata:
  name: example
spec:
  namespaces:
    - my-app
  enforcementPolicy:
    mode: enforce  # or "warn"
```

### SbomEnforcement

Denies pods whose SBOM contains specified components.

```yaml
apiVersion: policy.uds.dev/v1alpha1
kind: SbomEnforcement
metadata:
  name: example
spec:
  namespaces:
    - my-app
  enforcementPolicy:
    mode: enforce  # or "warn"
  deniedComponents:
    - name: log4j-core
      versionRange: "<2.17.0"
```

**Enforcement modes:**
- `enforce` -- reject pods that fail validation
- `warn` -- admit pods but return warnings

Only one policy of each type is allowed per namespace. Pods can opt out with the annotation `image-signature-policy/skip-verify: "true"`.

## Testing

### Unit tests

```bash
cd policy && npm install && npm run test:unit
```

### E2E tests

Requires a running cluster with the UDS bundle deployed.

```bash
make setup-e2e
make test-e2e
```

Run individual tests:

```bash
npx vitest run --config e2e/vitest.config.ts -t "ignores pods"
npx vitest run --config e2e/vitest.config.ts -t "annotates pods with signature"
npx vitest run --config e2e/vitest.config.ts -t "rejects unsigned"
npx vitest run --config e2e/vitest.config.ts -t "duplicate Signature"
```

## Make Targets

| Target | Description |
|---|---|
| `make build-policy` | Build Pepr module, consolidate chart with CRDs |
| `make crds` | Regenerate TypeScript classes from CRDs |
| `make setup-e2e` | Build test images, sign, create packages, deploy test fixtures |
| `make test-e2e` | Run e2e tests |
| `make clean` | Remove generated files |
