/**
 * Cosign SimpleSigning signature verification.
 *
 * Verifies that a container image has a valid cosign signature from a trusted
 * key by fetching the .sig tag artifact from the registry and performing
 * ECDSA signature verification using Node.js crypto.
 */

import { createVerify } from "crypto";
import { getBlob, getManifest, type RegistryConfig, type OciManifest } from "./registry.js";

const SIMPLESIGNING_MEDIA_TYPE =
  "application/vnd.dev.cosign.simplesigning.v1+json";
const SIGNATURE_ANNOTATION = "dev.cosignproject.cosign/signature";

export interface VerifyResult {
  verified: boolean;
  error?: string;
}

/**
 * Verify that an image has a valid cosign signature from any of the given
 * trusted public keys.
 *
 * The signature payload is fetched from the registry once and then checked
 * against every supplied key. Verification succeeds as soon as one key matches,
 * allowing applications signed with different private keys to be admitted as
 * long as their corresponding public key is trusted.
 *
 * @param registry - Registry host (e.g., "localhost:5000")
 * @param repo - Repository name (e.g., "example-app")
 * @param digest - Image digest (e.g., "sha256:abc123...")
 * @param publicKeys - One PEM-encoded public key, or an array of them
 * @param config - Registry connection config
 */
export async function verifyCosignSignature(
  registry: string,
  repo: string,
  digest: string,
  publicKeys: string | string[],
  config: RegistryConfig = {},
): Promise<VerifyResult> {
  const keys = (Array.isArray(publicKeys) ? publicKeys : [publicKeys]).filter(
    (k) => k && k.trim().length > 0,
  );
  if (keys.length === 0) {
    return { verified: false, error: `No trusted public keys configured` };
  }

  // Compute the .sig tag from the digest
  const digestHex = digest.replace("sha256:", "");
  const sigTag = `sha256-${digestHex}.sig`;

  // Fetch the .sig manifest
  let manifest: OciManifest;
  try {
    manifest = await getManifest(registry, repo, sigTag, config);
  } catch {
    return {
      verified: false,
      error: `No cosign signature found at ${repo}:${sigTag}`,
    };
  }

  // Find the SimpleSigning layer
  const sigLayer = manifest.layers.find(
    (l) => l.mediaType === SIMPLESIGNING_MEDIA_TYPE,
  );
  if (!sigLayer) {
    return {
      verified: false,
      error: `Signature manifest has no SimpleSigning layer`,
    };
  }

  // Extract the base64 signature from the layer annotation
  const signatureBase64 = sigLayer.annotations?.[SIGNATURE_ANNOTATION];
  if (!signatureBase64) {
    return {
      verified: false,
      error: `Signature layer missing ${SIGNATURE_ANNOTATION} annotation`,
    };
  }

  // Fetch the payload blob (the SimpleSigning JSON)
  let payload: Buffer;
  try {
    payload = await getBlob(registry, repo, sigLayer.digest, config);
  } catch {
    return {
      verified: false,
      error: `Failed to fetch signature payload blob`,
    };
  }

  // Verify the payload's claimed digest matches the image we're checking
  try {
    const payloadJson = JSON.parse(payload.toString("utf-8"));
    const claimedDigest =
      payloadJson?.critical?.image?.["docker-manifest-digest"];
    if (claimedDigest !== digest) {
      return {
        verified: false,
        error: `Signature payload claims digest ${claimedDigest}, expected ${digest}`,
      };
    }
  } catch {
    return {
      verified: false,
      error: `Failed to parse signature payload JSON`,
    };
  }

  // Verify the ECDSA signature against each trusted key; pass on the first match.
  for (const publicKeyPEM of keys) {
    try {
      const verifier = createVerify("SHA256");
      verifier.update(payload);
      if (verifier.verify(publicKeyPEM, signatureBase64, "base64")) {
        return { verified: true };
      }
    } catch {
      // Malformed key — skip it and try the next one.
    }
  }

  return {
    verified: false,
    error: `Signature verification failed — not signed by any of the ${keys.length} trusted key(s)`,
  };
}
