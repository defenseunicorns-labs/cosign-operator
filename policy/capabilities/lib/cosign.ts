/**
 * Cosign SimpleSigning signature verification.
 *
 * Verifies that a container image has a valid cosign signature from a trusted
 * key by fetching the .sig tag artifact from the registry and performing
 * ECDSA signature verification using Node.js crypto.
 */

import { createVerify } from "crypto";
import {
  getBlob,
  getManifest,
  type RegistryConfig,
} from "./registry.js";

const SIMPLESIGNING_MEDIA_TYPE =
  "application/vnd.dev.cosign.simplesigning.v1+json";
const SIGNATURE_ANNOTATION = "dev.cosignproject.cosign/signature";

export interface VerifyResult {
  verified: boolean;
  error?: string;
}

/**
 * Verify that an image has a valid cosign signature from the given public key.
 *
 * @param registry - Registry host (e.g., "localhost:5000")
 * @param repo - Repository name (e.g., "example-app")
 * @param digest - Image digest (e.g., "sha256:abc123...")
 * @param publicKeyPEM - PEM-encoded public key
 * @param config - Registry connection config
 */
export async function verifyCosignSignature(
  registry: string,
  repo: string,
  digest: string,
  publicKeyPEM: string,
  config: RegistryConfig = {},
): Promise<VerifyResult> {
  // Compute the .sig tag from the digest
  const digestHex = digest.replace("sha256:", "");
  const sigTag = `sha256-${digestHex}.sig`;

  // Fetch the .sig manifest
  let manifest;
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
    const claimedDigest = payloadJson?.critical?.image?.["docker-manifest-digest"];
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

  // Verify the ECDSA signature
  const verifier = createVerify("SHA256");
  verifier.update(payload);
  const isValid = verifier.verify(
    publicKeyPEM,
    signatureBase64,
    "base64",
  );

  if (!isValid) {
    return {
      verified: false,
      error: `Signature verification failed — not signed by the trusted key`,
    };
  }

  return { verified: true };
}
