import type { SBOMEnforcement, DeniedComponent } from "../generated/sbomenforcement-v1alpha1.js";

type HasNamespacesAndMode = {
  spec?: {
    namespaces: string[];
    enforcementPolicy: { mode: string };
  };
};

export type EnforcementMode = "enforce" | "warn";

/**
 * Returns the enforcement mode of the policy targeting the given namespace,
 * or null if no policy targets it. Only one policy per type per namespace
 * is allowed (enforced by admission).
 */
export function findMode(
  namespace: string,
  configs: Record<string, HasNamespacesAndMode>,
): EnforcementMode | null {
  for (const config of Object.values(configs)) {
    if (config.spec?.namespaces.includes(namespace)) {
      return config.spec.enforcementPolicy.mode as EnforcementMode;
    }
  }
  return null;
}

/**
 * Collects all denied components from SBOM enforcement policies targeting the given namespace.
 */
export function collectDeniedComponents(
  namespace: string,
  configs: Record<string, SBOMEnforcement>,
): DeniedComponent[] {
  const denied: DeniedComponent[] = [];
  for (const config of Object.values(configs)) {
    if (config.spec?.namespaces.includes(namespace)) {
      denied.push(...config.spec.deniedComponents);
    }
  }
  return denied;
}
