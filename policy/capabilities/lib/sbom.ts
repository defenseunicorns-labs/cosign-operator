import { getManifest, getBlob, type RegistryConfig } from "./registry.js";
// @ts-expect-error no type declarations for semver subpath export
import satisfies from "semver/functions/satisfies.js";
// @ts-expect-error no type declarations for semver subpath export
import validRange from "semver/ranges/valid.js";
import type { DeniedComponent } from "../generated/sbomenforcement-v1alpha1.js";

export interface SbomComponent {
  name: string;
  version: string;
}

export interface SbomCheckResult {
  violations: string[];
}

/**
 * Fetch and parse the SBOM attached to an image via the cosign `.sbom` tag.
 * Supports SPDX and CycloneDX JSON formats.
 */
export async function fetchSbomComponents(
  registry: string,
  repo: string,
  digest: string,
  config: RegistryConfig = {},
): Promise<SbomComponent[]> {
  const digestHex = digest.replace("sha256:", "");
  const sbomTag = `sha256-${digestHex}.sbom`;

  const manifest = await getManifest(registry, repo, sbomTag, config);

  if (!manifest.layers.length) {
    throw new Error(`SBOM manifest for ${repo}:${sbomTag} has no layers`);
  }

  const layer = manifest.layers[0];
  const blob = await getBlob(registry, repo, layer.digest, config);
  const doc = JSON.parse(blob.toString("utf-8"));

  return parseSbomDocument(doc);
}

/**
 * Extract components from an SPDX or CycloneDX JSON document.
 */
export function parseSbomDocument(doc: Record<string, unknown>): SbomComponent[] {
  // CycloneDX: { components: [{ name, version }] }
  if (Array.isArray(doc.components)) {
    return (doc.components as Array<{ name?: string; version?: string }>)
      .filter(c => c.name)
      .map(c => ({ name: c.name!, version: c.version ?? "" }));
  }

  // SPDX: { packages: [{ name, versionInfo }] }
  if (Array.isArray(doc.packages)) {
    return (doc.packages as Array<{ name?: string; versionInfo?: string }>)
      .filter(p => p.name)
      .map(p => ({ name: p.name!, version: p.versionInfo ?? "" }));
  }

  return [];
}

/**
 * Check a list of SBOM components against denied components.
 * Returns human-readable violation strings for each match.
 */
export function checkDeniedComponents(
  components: SbomComponent[],
  denied: DeniedComponent[],
): string[] {
  const violations: string[] = [];

  for (const d of denied) {
    for (const c of components) {
      if (c.name !== d.name) continue;

      if (d.versionRange === "*") {
        violations.push(`${c.name}@${c.version} is denied (all versions)`);
        continue;
      }

      if (validRange(d.versionRange)) {
        if (c.version && satisfies(c.version, d.versionRange)) {
          violations.push(
            `${c.name}@${c.version} is denied (matches ${d.versionRange})`,
          );
        }
      } else if (c.version === d.versionRange) {
        violations.push(
          `${c.name}@${c.version} is denied (exact match)`,
        );
      }
    }
  }

  return violations;
}
