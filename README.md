# Image Signature & SBOM Policy

**Note**:
_This is not a supported product by Defense Unicorns._

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
uds run build-policy
uds run create-package

# Create the UDS bundle
uds run create-bundle

# Create a cluster and deploy
k3d cluster create
uds deploy bundle/uds-bundle-image-signature-policy-amd64-0.0.2.tar.zst --confirm
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

#### Trusting multiple public keys

The operator trusts more than one cosign public key at a time, so applications
signed with **different private keys** can each be admitted without sharing a
single signing key. An image is admitted if its signature verifies against
**any** trusted key.

Trusted keys come from two sources, merged at runtime:

- the base key mounted at `/etc/cosign/cosign.pub` (or the `COSIGN_PUBLIC_KEY`
  env var), and
- any `Secret` in the `pepr-system` namespace labeled
  `pepr.dev/secret-type=cosign-public-key`.

To add another trusted key, upload its public key as a labeled Secret:

```bash
kubectl create secret generic my-team-cosign-pub \
  --namespace pepr-system \
  --from-file=cosign.pub=my-team.pub \
  --dry-run=client -o yaml \
  | kubectl label --local -f - pepr.dev/secret-type=cosign-public-key -o yaml \
  | kubectl apply -f -
```

A watch keeps the in-memory key array current — adding, updating, or deleting
these Secrets immediately changes the set of trusted keys (a Secret may contain
multiple PEM keys across its data entries).

### SBOMEnforcement

Denies pods whose SBOM contains specified components.

```yaml
apiVersion: policy.uds.dev/v1alpha1
kind: SBOMEnforcement
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
uds run setup-e2e
uds run test-e2e
```

Run individual tests:

```bash
npx vitest run --config e2e/vitest.config.ts -t "ignores pods"
npx vitest run --config e2e/vitest.config.ts -t "annotates pods with signature"
npx vitest run --config e2e/vitest.config.ts -t "rejects unsigned"
npx vitest run --config e2e/vitest.config.ts -t "second private key"
npx vitest run --config e2e/vitest.config.ts -t "duplicate Signature"
```

## UDS Tasks

| Target | Description |
|---|---|
| `uds run build-policy` | Build Pepr module, consolidate chart with CRDs |
| `uds run create-package` | Create the policy Zarf package |
| `uds run create-release-package` | Create the release Zarf package with SBOM generation |
| `uds run create-bundle` | Create the UDS bundle |
| `uds run setup-e2e` | Build test images, sign, create packages, deploy test fixtures |
| `uds run test-e2e` | Run e2e tests |
| `uds run clean` | Remove generated files |
