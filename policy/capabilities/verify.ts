/**
 * Image Signature Verification Policy
 *
 * Validates that every container image in an admitted Pod has a valid cosign
 * signature from a trusted public key. Follows UDS Core policy patterns.
 */

import { a, K8s, kind, Log } from "pepr";
import { readFileSync } from "fs";
import { When } from "./index.js";
import { verifyCosignSignature } from "./lib/cosign.js";
import { resolveDigest, type RegistryConfig } from "./lib/registry.js";

const SKIP_ANNOTATION = "image-signature-policy/skip-verify";
const COSIGN_KEY_PATH = "/etc/cosign/cosign.pub";

/** Load the cosign public key from the mounted secret, falling back to env var. */
function loadPublicKey(): string | null {
  try {
    return readFileSync(COSIGN_KEY_PATH, "utf-8");
  } catch {
    // Fall back to env var
  }
  return process.env.COSIGN_PUBLIC_KEY ?? null;
}

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
    return {
      config: {
        allowHttp: true,
        username: zarfInfo.pullUsername,
        password: zarfInfo.pullPassword,
      },
      resolvedRegistry: "zarf-docker-registry.zarf.svc.cluster.local:5000",
    };
  }

  // Non-Zarf registry — no auth, HTTPS by default
  return { config: {}, resolvedRegistry: registry };
}

/**
 * Validate that all container images in a Pod have valid cosign signatures.
 */
When(a.Pod)
  .IsCreatedOrUpdated()
  .Validate(async (request) => {
    // Allow pods with the skip annotation
    if (request.HasAnnotation(SKIP_ANNOTATION)) {
      Log.info(
        `Pod ${request.Raw.metadata?.name} has ${SKIP_ANNOTATION} annotation, skipping verification`,
      );
      return request.Approve();
    }

    const publicKey = loadPublicKey();
    if (!publicKey) {
      return request.Deny(
        "Image signature policy misconfigured: no cosign public key found (checked /etc/cosign/cosign.pub and COSIGN_PUBLIC_KEY env var)",
      );
    }

    // Collect all container images (containers + initContainers + ephemeral)
    const allContainers = [
      ...(request.Raw.spec?.containers ?? []),
      ...(request.Raw.spec?.initContainers ?? []),
    ];

    const errors: string[] = [];

    for (const container of allContainers) {
      const image = container.image;
      if (!image) continue;

      const parsed = parseImageRef(image);
      if (!parsed) {
        errors.push(`${container.name}: unable to parse image ref "${image}"`);
        continue;
      }

      try {
        const { config, resolvedRegistry } = await registryConfig(
          parsed.registry,
        );

        // Resolve tag to digest if needed
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
          errors.push(`${container.name} (${image}): ${result.error}`);
        } else {
          Log.info(`Verified signature for ${image}`);
        }
      } catch (err) {
        errors.push(
          `${container.name} (${image}): verification error: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    if (errors.length > 0) {
      return request.Deny(
        `Image signature verification failed:\n${errors.join("\n")}`,
      );
    }

    return request.Approve();
  });
