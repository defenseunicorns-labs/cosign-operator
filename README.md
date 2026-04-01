# Zarf SBOM + Image Signature Verification

Demonstrates an end-to-end workflow for building, signing, and deploying container images with [Zarf](https://zarf.dev), then enforcing image signature verification at admission time with a [Pepr](https://pepr.dev) policy.

## What's in the box

- **Example app** -- a simple nginx container, cosign-signed with an SBOM attestation, packaged as a Zarf package
- **Pepr admission policy** -- a ValidatingWebhook that verifies every pod's container images have a valid cosign signature from a trusted public key
- **Make targets** for the full build/sign/deploy/test lifecycle

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Zarf](https://docs.zarf.dev/getting-started/)
- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
- [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
- [syft](https://github.com/anchore/syft)
- [Node.js](https://nodejs.org/) (for Pepr)
- A running Kubernetes cluster with Zarf initialized (e.g., [UDS Core](https://github.com/defenseunicorns/uds-core) on k3d)
- A local OCI registry (default: `localhost:5000`)

## Quick start

### 1. Generate cosign keys

```sh
COSIGN_PASSWORD="" make keys
```

### 2. Build, sign, and package

This builds the container image, pushes it to the local registry, signs it with cosign, generates an SBOM with syft, attests the SBOM, and creates the Zarf package:

```sh
make all
```

### 3. Deploy the Pepr policy

Installs the Pepr admission webhook, creates a Kubernetes Secret with the cosign public key, and mounts it into the Pepr controller:

```sh
cd policy && npm install && cd ..
make deploy-policy
```

### 4. Deploy the signed app

```sh
zarf package deploy zarf-package-example-signed-app-amd64-0.0.1.tar.zst --confirm
```

### 5. Test the policy

Run both positive (signed image allowed) and negative (unsigned image rejected) tests:

```sh
make test-policy
```

Or run them individually:

```sh
make test-policy-positive   # deploys the signed package -- should succeed
make test-policy-negative   # deploys an unsigned nginx image -- should be rejected
```

## Make targets

| Target | Description |
|---|---|
| `make all` | Build, push, sign, attest, and create the Zarf package |
| `make keys` | Generate a cosign key pair |
| `make build` | Build the container image |
| `make push` | Push the image to the local registry |
| `make sign-and-package` | Sign, generate SBOM, attest, render templates, create Zarf package |
| `make verify` | Verify the cosign signature and SBOM attestation against the source registry |
| `make deploy-policy` | Deploy the Pepr image signature policy to the cluster |
| `make test-policy` | Run positive and negative policy tests |
| `make test-policy-positive` | Deploy the signed Zarf package (should succeed) |
| `make test-policy-negative` | Deploy an unsigned Zarf package (should be rejected) |
| `make clean` | Remove generated files |

## Configuration

The Makefile supports the following variables:

```sh
REGISTRY=localhost:5000    # Source OCI registry
IMAGE_NAME=example-app     # Image name
IMAGE_TAG=latest           # Image tag
COSIGN_KEY=cosign.key      # Path to cosign private key
COSIGN_PUB=cosign.pub      # Path to cosign public key
```

Override them as needed:

```sh
make all REGISTRY=myregistry.example.com:5000
```

## How it works

### Image signing

The `sign-and-package` target:

1. Resolves the image digest with `crane`
2. Signs the image by digest with `cosign sign` using legacy tag-based storage (`.sig` tags) -- this is what Zarf expects
3. Generates an SPDX SBOM with `syft`
4. Attests the SBOM with `cosign attest` (stored as an `.att` tag)
5. Renders `zarf.yaml` and deployment manifests from templates, pinning the image by digest
6. Creates the Zarf package, including the image, signature, and attestation artifacts

### Pepr policy

The policy (`policy/`) is a Pepr module that registers a `ValidatingWebhook` on Pod create/update. For each container image:

1. Parses the image reference from the pod spec
2. Auto-discovers the Zarf internal registry address and credentials from the `zarf-state` secret (no manual configuration needed)
3. Looks up the cosign `.sig` tag in the registry
4. Verifies the signature against the trusted public key using ECDSA
5. Approves the pod if all images pass, or denies with a detailed error message

The public key is loaded from a mounted Kubernetes Secret at `/etc/cosign/cosign.pub`, with a fallback to the `COSIGN_PUBLIC_KEY` environment variable.

Pods can opt out of verification with the annotation `image-signature-policy/skip-verify`.

### Project structure

```
.
├── Dockerfile                      # Example app (nginx-unprivileged)
├── index.html                      # Example app content
├── Makefile                        # Build/sign/deploy/test automation
├── cosign.key / cosign.pub         # Cosign key pair (generated, git-ignored)
├── zarf.yaml.tmpl                  # Zarf package template
├── manifests/
│   ├── deployment.yaml.tmpl        # Deployment template (image pinned by digest)
│   └── service.yaml                # Service definition
├── policy/                         # Pepr admission policy
│   ├── pepr.ts                     # Pepr module entrypoint
│   ├── package.json                # Pepr config and dependencies
│   ├── tsconfig.json
│   └── capabilities/
│       ├── index.ts                # Capability definition
│       ├── verify.ts               # Admission webhook logic
│       └── lib/
│           ├── cosign.ts           # Cosign signature verification
│           └── registry.ts         # OCI registry client
└── test/
    └── unsigned/                   # Negative test fixture
        ├── zarf.yaml               # Unsigned image Zarf package
        └── deployment.yaml
```
