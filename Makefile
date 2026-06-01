REGISTRY   ?= localhost:5000
IMAGE_NAME ?= example-app
IMAGE_TAG  ?= latest
COSIGN_KEY ?= cosign.key
COSIGN_PUB ?= cosign.pub

FULL_IMAGE = $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: all clean crds keys build push sign-and-package verify deploy-policy build-policy test-policy test-policy-positive test-policy-negative test-e2e

# Full workflow: build, push, sign, generate SBOM, attest, create Zarf package
all: build push sign-and-package

# Generate cosign key pair (run once, requires COSIGN_PASSWORD env var)
keys:
	cosign generate-key-pair

# Build the container image
build:
	docker build -t $(FULL_IMAGE) .

# Generate TypeScript classes from CRDS
crds:
	npx kubernetes-fluent-client crd chart/crds/signature.crd.yaml policy/capabilities/generated/
	npx kubernetes-fluent-client crd chart/crds/sbom.crd.yaml policy/capabilities/generated/

# Push to the source registry
push:
	docker push $(FULL_IMAGE)

# Sign, generate SBOM, attest, render templates, and create Zarf package.
# Runs in a single shell because every step depends on the image digest.
# --new-bundle-format=false makes cosign use legacy tag-based storage
# (.sig/.att tags) instead of OCI referrers, which is what Zarf expects.
sign-and-package:
	@set -euo pipefail; \
	DIGEST=$$(crane digest $(FULL_IMAGE)); \
	DIGEST_HEX=$${DIGEST#sha256:}; \
	IMAGE_REF="$(REGISTRY)/$(IMAGE_NAME)@$${DIGEST}"; \
	IMAGE_SIG="$(REGISTRY)/$(IMAGE_NAME):sha256-$${DIGEST_HEX}.sig"; \
	IMAGE_ATT="$(REGISTRY)/$(IMAGE_NAME):sha256-$${DIGEST_HEX}.att"; \
	IMAGE_NAME_TAGGED="$(FULL_IMAGE)"; \
	echo "==> Digest: $${DIGEST}"; \
	echo "==> Signing image..."; \
	COSIGN_PASSWORD="" cosign sign --key $(COSIGN_KEY) \
		--new-bundle-format=false --use-signing-config=false --tlog-upload=false $${IMAGE_REF}; \
	echo "==> Generating SBOM with syft..."; \
	syft scan $${IMAGE_REF} -o spdx-json=sbom.spdx.json; \
	echo "==> Attesting SBOM..."; \
	COSIGN_PASSWORD="" cosign attest --key $(COSIGN_KEY) --predicate sbom.spdx.json \
		--type spdxjson --new-bundle-format=false --use-signing-config=false --tlog-upload=false $${IMAGE_REF}; \
	echo "==> Generating zarf.yaml and manifests..."; \
	export IMAGE_REF IMAGE_SIG IMAGE_ATT IMAGE_NAME_TAGGED; \
	envsubst < zarf.yaml.tmpl > zarf.yaml; \
	envsubst < manifests/deployment.yaml.tmpl > manifests/deployment.yaml; \
	echo "==> Generated zarf.yaml:"; \
	cat zarf.yaml; \
	echo "==> Creating Zarf package..."; \
	zarf package create . --confirm --skip-sbom

# kubectl run crane-check --rm -it --restart=Never -l zarf.dev/agent=ignore --image=gcr.io/go-containerregistry/crane -- ls --insecure -u zarf-pull -p 'jpo1v!V01ZdCMx1QPvDdJik7' zarf-docker-registry.zarf.svc.cluster.local:5000/e2e-app
# kubectl run reg-check --rm -it --restart=Never -l zarf.dev/agent=ignore --image=curlimages/curl -- -s -u 'zarf-pull:jpo1v!V01ZdCMx1QPvDdJik7' http://zarf-docker-registry.zarf.svc.cluster.local:5000/v2/e2e-app/tags/list
# Verify signature and SBOM attestation
verify:
	@set -euo pipefail; \
	DIGEST=$$(crane digest $(FULL_IMAGE)); \
	IMAGE_REF="$(REGISTRY)/$(IMAGE_NAME)@$${DIGEST}"; \
	echo "==> Verifying signature..."; \
	cosign verify --key $(COSIGN_PUB) --insecure-ignore-tlog=true $${IMAGE_REF}; \
	echo "==> Verifying SBOM attestation..."; \
	cosign verify-attestation --key $(COSIGN_PUB) --type spdxjson \
		--insecure-ignore-tlog=true $${IMAGE_REF}

# Build Pepr module, consolidate chart with CRDs, and copy zarf.yaml to root
build-policy:
	cd policy && npx pepr build --zarf chart --custom-name cosign-hook
	cp policy/dist/image-signature-policy-chart/Chart.yaml chart/
 	#custom for this module - DO NOT DELETE - cp policy/dist/image-signature-policy-chart/values.yaml chart/ 
 	#custom for this module - DO NOT DELETE - cp policy/dist/image-signature-policy-chart/values.schema.json chart/
	cp -r policy/dist/image-signature-policy-chart/charts chart/
	mkdir -p /tmp/pepr-chart-preserve
	cp chart/templates/cosign-secret.yaml chart/templates/package.yaml /tmp/pepr-chart-preserve/
	cp -r policy/dist/image-signature-policy-chart/templates chart/
	cp /tmp/pepr-chart-preserve/cosign-secret.yaml /tmp/pepr-chart-preserve/package.yaml chart/templates/
	rm -rf /tmp/pepr-chart-preserve
	@# Generate cosign keys if they don't already exist
	@test -f $(COSIGN_KEY) || COSIGN_PASSWORD="" cosign generate-key-pair
	@# Patch hash, apiPath, and cosignPublicKey into chart/values.yaml
	@set -e; \
	HASH=$$(grep "^hash:" policy/dist/image-signature-policy-chart/values.yaml | sed "s/hash: '//;s/'//;s/ //g"); \
	API_PATH=$$(grep "apiPath:" policy/dist/image-signature-policy-chart/values.yaml | sed "s/.*apiPath: '//;s/'//"); \
	COSIGN_B64=$$(base64 -w0 $(COSIGN_PUB)); \
	sed -i "s|^hash: '.*'|hash: '$$HASH'|" chart/values.yaml; \
	sed -i "s|apiPath: '.*'|apiPath: '$$API_PATH'|" chart/values.yaml; \
	sed -i "s|cosignPublicKey: '.*'|cosignPublicKey: '$$COSIGN_B64'|" chart/values.yaml
	cp policy/dist/zarf.yaml zarf.yaml
	sed -i 's|localPath: image-signature-policy-chart|localPath: chart|' zarf.yaml
	sed -i 's|0.0.1|0.0.2|' zarf.yaml
	sed -i '0,/localPath: chart/{s|localPath: chart|localPath: chart\n        noWait: true|}' zarf.yaml
	@echo "==> Built chart at chart/ (CRDs deploy first via Helm convention)"
	@echo "==> Zarf config at zarf.yaml"

# Deploy the Pepr image signature policy
deploy-policy:
	@echo "==> Creating cosign public key secret..."
	kubectl create secret generic cosign-public-key \
		--namespace pepr-system \
		--from-file=cosign.pub=$(COSIGN_PUB) \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "==> Deploying Pepr module..."
	cd policy && npx pepr deploy --yes
	@echo "==> Mounting cosign public key into Pepr deployment..."
	kubectl -n pepr-system patch deployment pepr-image-signature-policy --type=json -p '[{"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"cosign-key","secret":{"secretName":"cosign-public-key"}}},{"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"cosign-key","mountPath":"/etc/cosign","readOnly":true}}]'
	@echo "==> Waiting for rollout..."
	kubectl -n pepr-system rollout status deployment/pepr-image-signature-policy

# Test the Pepr image signature policy (positive + negative)
test-policy: test-policy-positive test-policy-negative

# Test that signed images are allowed
test-policy-positive:
	@echo "==> Test: Signed image should be ALLOWED"
	@echo "    Deploying signed Zarf package..."
	@zarf package deploy zarf-package-example-signed-app-*.tar.zst --confirm --timeout 60s
	@echo "    PASS: Signed image was allowed"

# Test that unsigned images are rejected
test-policy-negative:
	@echo "==> Test: Unsigned image should be REJECTED"
	@echo "    Building unsigned test Zarf package..."
	@cd test/unsigned && zarf package create . --confirm --skip-sbom -o .
	@echo "    Deploying unsigned package (expect timeout — policy should block pods)..."
	@cd test/unsigned && zarf package deploy zarf-package-unsigned-test-app-*.tar.zst --confirm --timeout 15s 2>&1 || true
	@echo ""
	@echo "    Checking ReplicaSet for rejection reason..."
	@kubectl -n unsigned-test get replicaset -o jsonpath='{range .items[*]}{.status.conditions[*].message}{"\n"}{end}' 2>/dev/null | tee /tmp/unsigned-test-result.log
	@grep -q -i "signature verification failed" /tmp/unsigned-test-result.log \
		&& echo "    PASS: Unsigned image was rejected by policy" \
		|| echo "    FAIL: Unsigned image was not rejected by policy"
	@echo "    Cleaning up..."
	@kubectl delete namespace unsigned-test --ignore-not-found 2>/dev/null || true
	@rm -f test/unsigned/zarf-package-*.tar.zst

# Setup e2e: registry, build, sign, package, namespaces, CRDs
setup-e2e:
	./e2e/setup.sh

# Run e2e tests (run setup-e2e first)
test-e2e:
	npx vitest run --config e2e/vitest.config.ts

# Remove generated files
clean:
	rm -f zarf.yaml manifests/deployment.yaml sbom.spdx.json
	rm -f zarf-package-*.tar.zst
	rm -f test/unsigned/zarf-package-*.tar.zst
	rm -rf policy/dist/
