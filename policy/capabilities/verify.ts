/**
 * Image Signature Verification Policy
 *
 * Validates that every container image in an admitted Pod has a valid cosign
 * signature from a trusted public key. Follows UDS Core policy patterns.
 */

import { a, K8s, kind, Log, sdk } from "pepr";
import { readFileSync } from "fs";
import { When } from "./index.js";
import { verifyCosignSignature } from "./lib/cosign.js";
import { resolveDigest, type RegistryConfig } from "./lib/registry.js";
import { shouldUpdateStatus, buildReadyStatus } from "./lib/status.js";
import { findMode, collectDeniedComponents } from "./lib/policy.js";
import { fetchSbomComponents, checkDeniedComponents } from "./lib/sbom.js";
import { SBOMEnforcement } from "./generated/sbomenforcement-v1alpha1.js";
import { SignatureEnforcement } from "./generated/signatureenforcement-v1alpha1.js";

const { containers } = sdk;

const SKIP_ANNOTATION = "image-signature-policy/skip-verify";
const COSIGN_KEY_PATH = "/etc/cosign/cosign.pub";
const SigConfig: Record<string, SignatureEnforcement> = {};
const SbomConfig: Record<string, SBOMEnforcement> = {};

/** Cached cosign public key, loaded once at startup. */
let cachedPublicKey: string | null | undefined;
function loadPublicKey(): string | null {
  if (cachedPublicKey !== undefined) return cachedPublicKey;
  try {
    cachedPublicKey = readFileSync(COSIGN_KEY_PATH, "utf-8");
  } catch {
    cachedPublicKey = process.env.COSIGN_PUBLIC_KEY ?? null;
  }
  console.log(`Loaded cosign public key: ${cachedPublicKey}`);
  return cachedPublicKey;
}
loadPublicKey(); // Load at startup so it's ready for the first request
loadZarfRegistryInfo();
(async () => {
  new Promise((resolve) => setTimeout(resolve, 1000)).then(() => {
    console.log({ zarfRegistryInfo }, "Initial Zarf registry info:");
    console.log({ SigConfig }, "Initial Signature Enforcement configs:");
    console.log({ SbomConfig }, "Initial SBOM Enforcement configs:");
  });
})();
/** Parse an image reference into registry, repository, tag, and digest. */
function parseImageRef(imageRef: string): {
  registry: string;
  repo: string;
  tag?: string;
  digest?: string;
} | null {
  if (!imageRef) return null;

  const trimmed = imageRef.trim();
  if (!trimmed) return null;

  // Split off digest (@sha256:...)
  let digest: string | undefined;
  let rest = trimmed;
  const atIdx = rest.indexOf("@");
  if (atIdx !== -1) {
    digest = rest.slice(atIdx + 1);
    rest = rest.slice(0, atIdx);
  }

  // Split off tag (:tag)
  let tag: string | undefined;
  const colonIdx = rest.lastIndexOf(":");
  if (colonIdx !== -1) {
    const afterColon = rest.slice(colonIdx + 1);
    // Only treat as tag if it doesn't contain "/" (to avoid registry port)
    if (!afterColon.includes("/")) {
      tag = afterColon;
      rest = rest.slice(0, colonIdx);
    }
  }

  // Split registry from repository
  const parts = rest.split("/");
  const firstPart = parts[0];
  const isRegistry =
    firstPart.includes(".") ||
    firstPart.includes(":") ||
    firstPart === "localhost";

  let registry: string;
  let repo: string;
  if (isRegistry) {
    registry = firstPart;
    repo = parts.slice(1).join("/");
    if (!repo) return null;
  } else {
    registry = "docker.io";
    repo = rest;
  }

  if (!digest && !tag) {
    tag = "latest";
  }

  return { registry, repo, tag, digest };
}

/** Cached Zarf registry info, loaded once from the zarf-state secret. */
let zarfRegistryInfo: {
  address: string;
  pullUsername: string;
  pullPassword: string;
} | null = null;

async function loadZarfRegistryInfo(): Promise<typeof zarfRegistryInfo> {
  if (zarfRegistryInfo) return zarfRegistryInfo;

  try {
    const secret = await K8s(kind.Secret).InNamespace("zarf").Get("zarf-state");
    const stateB64 = secret.data?.state;
    if (!stateB64) return null;

    const state = JSON.parse(Buffer.from(stateB64, "base64").toString("utf-8"));
    const ri = state.registryInfo;
    if (ri) {
      zarfRegistryInfo = {
        address: ri.address,
        pullUsername: ri.pullUsername,
        pullPassword: ri.pullPassword,
      };
      Log.info(`Loaded Zarf registry info: ${ri.address}`);
    }
    return zarfRegistryInfo;
  } catch (err) {
    Log.warn(`Error loading zarf-state: ${err}`);
    return null;
  }
}

/**
 * Build a RegistryConfig for the given registry address.
 * Auto-discovers Zarf internal registry credentials from the zarf-state secret
 * and remaps the address to the in-cluster service.
 */
async function registryConfig(
  registry: string,
): Promise<{ config: RegistryConfig; resolvedRegistry: string }> {
  const zarfInfo = await loadZarfRegistryInfo();

  if (zarfInfo && registry === zarfInfo.address) {
    // Use in-cluster service name when running in-cluster, otherwise keep the original address
    const inCluster = process.env.KUBERNETES_SERVICE_HOST;
    return {
      config: {
        allowHttp: true,
        username: zarfInfo.pullUsername,
        password: zarfInfo.pullPassword,
      },
      resolvedRegistry: inCluster
        ? "zarf-docker-registry.zarf.svc.cluster.local:5000"
        : zarfInfo.address,
    };
  }

  // Non-Zarf registry — no auth, HTTPS by default
  return { config: {}, resolvedRegistry: registry };
}

/**
 * Annotate pods targeted by any enforcement policy so it is visible that
 * the controller has evaluated them.
 */
When(a.Pod)
  .IsCreatedOrUpdated()
  .Mutate((request) => {
    const ns = request.Raw.metadata!.namespace!;

    const sigMode = findMode(ns, SigConfig);
    const sbomMode = findMode(ns, SbomConfig);

    if (sigMode) {
      request.SetAnnotation(
        "signatureenforcements.policy.uds.dev",
        new Date().toISOString(),
      );
    }
    if (sbomMode) {
      request.SetAnnotation(
        "sbomenforcements.policy.uds.dev",
        new Date().toISOString(),
      );
    }
  });

/**
 * Validate that all container images in a Pod satisfy the enforcement policies
 * defined by SignatureEnforcement and SBOMEnforcement CRs.
 *
 * - No matching CRDs for the namespace → approve (no policy).
 * - Mode "enforce" → deny on failure.
 * - Mode "warn"   → approve with warnings on failure.
 */
When(a.Pod)
  .IsCreatedOrUpdated()
  .Validate(async (request) => {
    if (request.HasAnnotation(SKIP_ANNOTATION)) {
      Log.info(
        `Pod ${request.Raw.metadata?.name} has ${SKIP_ANNOTATION} annotation, skipping verification`,
      );
      return request.Approve();
    }

    const ns = request.Raw.metadata!.namespace!;

    const sigMode = findMode(ns, SigConfig);
    const sbomMode = findMode(ns, SbomConfig);

    // No enforcement policies target this namespace
    if (!sigMode && !sbomMode) return request.Approve();

    const errors: string[] = [];
    const warnings: string[] = [];
    const allContainers = containers(request);
    // --- Signature verification ---
    if (sigMode) {
      const publicKey = loadPublicKey();
      if (!publicKey) {
        const msg =
          "Image signature policy misconfigured: no cosign public key found";
        if (sigMode === "enforce") {
          errors.push(msg);
        } else {
          warnings.push(msg);
        }
      } else {
        for (const container of allContainers) {
          const image = container.image;
          if (!image) continue;

          const parsed = parseImageRef(image);
          if (!parsed) {
            const msg = `${container.name}: unable to parse image ref "${image}"`;
            sigMode === "enforce" ? errors.push(msg) : warnings.push(msg);
            continue;
          }

          try {
            const { config, resolvedRegistry } = await registryConfig(
              parsed.registry,
            );

            let digest = parsed.digest;
            if (!digest) {
              digest = await resolveDigest(
                resolvedRegistry,
                parsed.repo,
                parsed.tag ?? "latest",
                config,
              );
            }

            const result = await verifyCosignSignature(
              resolvedRegistry,
              parsed.repo,
              digest,
              publicKey,
              config,
            );

            if (!result.verified) {
              const msg = `${container.name} (${image}): ${result.error}`;
              sigMode === "enforce" ? errors.push(msg) : warnings.push(msg);
            } else {
              Log.info(`Verified signature for ${image}`);
            }
          } catch (err) {
            const msg = `${container.name} (${image}): verification error: ${err instanceof Error ? err.message : String(err)}`;
            sigMode === "enforce" ? errors.push(msg) : warnings.push(msg);
          }
        }
      }
    }

    // --- SBOM verification ---
    if (sbomMode) {
      const denied = collectDeniedComponents(ns, SbomConfig);

      for (const container of allContainers) {
        const image = container.image;
        if (!image) continue;

        const parsed = parseImageRef(image);
        if (!parsed) {
          const msg = `${container.name}: unable to parse image ref "${image}"`;
          sbomMode === "enforce" ? errors.push(msg) : warnings.push(msg);
          continue;
        }

        try {
          const { config, resolvedRegistry } = await registryConfig(
            parsed.registry,
          );

          let digest = parsed.digest;
          if (!digest) {
            digest = await resolveDigest(
              resolvedRegistry,
              parsed.repo,
              parsed.tag ?? "latest",
              config,
            );
          }

          const components = await fetchSbomComponents(
            resolvedRegistry,
            parsed.repo,
            digest,
            config,
          );

          const violations = checkDeniedComponents(components, denied);
          for (const v of violations) {
            const msg = `${container.name} (${image}): ${v}`;
            sbomMode === "enforce" ? errors.push(msg) : warnings.push(msg);
          }
        } catch (err) {
          const msg = `${container.name} (${image}): SBOM check failed: ${err instanceof Error ? err.message : String(err)}`;
          sbomMode === "enforce" ? errors.push(msg) : warnings.push(msg);
        }
      }
    }

    if (errors.length > 0) {
      return request.Deny(
        `Policy enforcement failed:\n${errors.join("\n")}`,
        undefined,
        warnings.length > 0 ? warnings : undefined,
      );
    }

    return request.Approve(warnings.length > 0 ? warnings : undefined);
  });

if (
  process.env.PEPR_WATCH_MODE === "false" ||
  process.env.PEPR_MODE === "dev"
) {
  /**
   * Watch for changes to SignatureEnforcement and store them
   */
  const sigWatch = K8s(SignatureEnforcement).Watch(async (sigEnforce, phase) => {
    if (phase === "DELETED") return; 
    const generation = sigEnforce.metadata?.generation;
    const observed = sigEnforce.status?.observedGeneration;
    SigConfig[sigEnforce.metadata!.name] = sigEnforce;
    if (!shouldUpdateStatus(generation, observed)) return;

    Log.info({ sigEnforce }, `Storing SignatureEnforcement`);

    await K8s(SignatureEnforcement).PatchStatus({
      metadata: { name: sigEnforce.metadata!.name },
      status: buildReadyStatus(generation ?? 0),
    });
  });
  sigWatch.start();

  /**
   * Watch for changes to SBOMEnforcement and store them
   */
  const sbomWatch = K8s(SBOMEnforcement).Watch(async (sbomEnforce, phase) => {
    if (phase === "DELETED") return; 
    const generation = sbomEnforce.metadata?.generation;
    const observed = sbomEnforce.status?.observedGeneration;
    SbomConfig[sbomEnforce.metadata!.name] = sbomEnforce;
    if (!shouldUpdateStatus(generation, observed)) return;
    Log.info({ sbomEnforce }, `Storing SBOMEnforcement`);

    await K8s(SBOMEnforcement).PatchStatus({
      metadata: { name: sbomEnforce.metadata!.name },
      status: buildReadyStatus(generation ?? 0),
    });
  });
  sbomWatch.start();

  const sbomDeleteWatch = K8s(SBOMEnforcement).Watch(async (sbomEnforce, phase) => {
    if (phase !== "DELETED") return;
    Log.info({ sbomEnforce }, `Removing SBOMEnforcement`);
    delete SbomConfig[sbomEnforce.metadata!.name];
  });
  sbomDeleteWatch.start();

  const sigDeleteWatch = K8s(SignatureEnforcement).Watch(async (sigEnforce, phase) => {
    if (phase !== "DELETED") return;
    Log.info({ sigEnforce }, `Removing SignatureEnforcement`);
    delete SigConfig[sigEnforce.metadata!.name];
  });
  sigDeleteWatch.start();

  const publicKeyWatch = K8s(kind.Secret).InNamespace("pepr-system").WithLabel("pepr.dev/secret-type", "cosign-public-key").Watch(async (secret, phase) => {
    if (phase === "DELETED") {
      Log.warn(`Cosign public key secret ${secret.metadata?.name} deleted, clearing cached public key`);
      cachedPublicKey = null;
      return;
    }
    if (phase === "ADDED" || phase === "MODIFIED") {
      Log.info(`Cosign public key secret ${secret.metadata?.name} added/modified, reloading public key`);
      cachedPublicKey = undefined; // force reload
      loadPublicKey();
    }
  });
  publicKeyWatch.start();
}

/**
 * Ensure only one SignatureEnforcement exists per namespace, and reject if one already exists.
 */
When(SignatureEnforcement)
  .IsCreated()
  .Validate((sigEnforce) => {
    const requestedNs = sigEnforce.Raw.spec?.namespaces ?? [];
    const conflicts = requestedNs.filter(
      (ns) => findMode(ns, SigConfig) !== null,
    );

    if (conflicts.length > 0) {
      return sigEnforce.Deny(
        `A SignatureEnforcement already exists for namespace(s): ${conflicts.join(", ")}`,
      );
    }

    return sigEnforce.Approve();
  });

/**
 * Ensure only one SBOMEnforcement exists per namespace, and reject if one already exists.
 */
When(SBOMEnforcement)
  .IsCreated()
  .Validate((sbomEnforce) => {
    const requestedNs = sbomEnforce.Raw.spec?.namespaces ?? [];
    const conflicts = requestedNs.filter(
      (ns) => findMode(ns, SbomConfig) !== null,
    );

    if (conflicts.length > 0) {
      return sbomEnforce.Deny(
        `An SBOMEnforcement already exists for namespace(s): ${conflicts.join(", ")}`,
      );
    }

    return sbomEnforce.Approve();
  });
