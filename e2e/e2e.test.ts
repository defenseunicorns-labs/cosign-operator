import { describe, it, expect } from "vitest";
import { execSync } from "child_process";
import { join } from "path";

const ROOT = join(import.meta.dirname, "..");
const E2E = join(ROOT, "e2e");
const RESOLVED = join(E2E, "resolved");
const CRS_DUP = join(E2E, "manifests", "crs-dup");

function run(cmd: string, opts?: { ignoreError?: boolean; timeout?: number }): string {
  try {
    return execSync(cmd, {
      cwd: ROOT,
      encoding: "utf-8",
      timeout: opts?.timeout ?? 30000,
    }).trim();
  } catch (e: any) {
    if (opts?.ignoreError) {
      return (e.stderr?.toString?.() ?? "") + (e.stdout?.toString?.() ?? "");
    }
    throw e;
  }
}

function kubectl(cmd: string, ignoreError = false): string {
  return run(`kubectl ${cmd}`, { ignoreError });
}

function deploy(type: string, ns: string): void {
  kubectl(`apply -f ${RESOLVED}/${type}-${ns}.yaml`);
}

function sleep(sec: number): void {
  execSync(`sleep ${sec}`);
}

function podIsRunning(ns: string, label: string, timeoutSec = 60): boolean {
  try {
    kubectl(`wait --for=condition=Ready pod -l ${label} -n ${ns} --timeout=${timeoutSec}s`);
    return true;
  } catch {
    return false;
  }
}

function getPodAnnotation(ns: string, label: string, key: string): string {
  const escaped = key.replace(/\./g, "\\.");
  return kubectl(
    `get pod -l ${label} -n ${ns} -o jsonpath='{.items[0].metadata.annotations.${escaped}}'`,
    true,
  );
}

function getReplicaSetEvents(ns: string): string {
  return kubectl(
    `get events -n ${ns} --field-selector reason=FailedCreate -o jsonpath='{.items[*].message}'`,
    true,
  );
}

// ---------------------------------------------------------------------------
// Tests — assumes e2e/setup.sh has already run
// ---------------------------------------------------------------------------

describe("E2E Policy Enforcement", { timeout: 300_000 }, () => {
  it("ignores pods when no enforcement CRDs target the namespace", { timeout: 30000 }, () => {
    expect(podIsRunning("e2e-no-policy", "app=e2e-signed-app")).toBe(true);
    expect(getPodAnnotation("e2e-no-policy", "app=e2e-signed-app", "signatureenforcements.policy.uds.dev")).toBe("");
    expect(getPodAnnotation("e2e-no-policy", "app=e2e-signed-app", "sbomenforcements.policy.uds.dev")).toBe("");
  });

  it("annotates pods with signatureenforcements.policy.uds.dev when SignatureEnforcement exists", { timeout: 30000 }, () => {
    // Deployed by setup.sh via Zarf AFTER CRs were applied
    expect(podIsRunning("e2e-sig-enforce", "app=e2e-signed-app")).toBe(true);
    expect(getPodAnnotation("e2e-sig-enforce", "app=e2e-signed-app", "signatureenforcements.policy.uds.dev")).not.toBe("");
  });

  it("annotates pods with sbomenforcements.policy.uds.dev when SBOMEnforcement exists", { timeout: 30000 }, () => {
    // Deployed by setup.sh via Zarf AFTER CRs were applied
    expect(podIsRunning("e2e-sbom-mutate", "app=e2e-signed-app")).toBe(true);
    expect(getPodAnnotation("e2e-sbom-mutate", "app=e2e-signed-app", "sbomenforcements.policy.uds.dev")).not.toBe("");
  });

  it("rejects unsigned images when SignatureEnforcement mode is enforce", { timeout: 30000 }, () => {
    deploy("unsigned-app", "e2e-unsigned-reject");
    sleep(5);

    expect(podIsRunning("e2e-unsigned-reject", "app=e2e-unsigned-app", 10)).toBe(false);
    expect(getReplicaSetEvents("e2e-unsigned-reject").toLowerCase()).toMatch(
      /policy enforcement failed|signature/i,
    );
  });

  it("admits unsigned images with warnings when SignatureEnforcement mode is warn", { timeout: 30000 }, () => {
    expect(podIsRunning("e2e-unsigned-warn", "app=e2e-unsigned-app")).toBe(true);
  });

  it("rejects pods when SBOM contains denied components in enforce mode", { timeout: 30000 }, () => {
    deploy("signed-app", "e2e-sbom-deny");
    sleep(5);

    expect(podIsRunning("e2e-sbom-deny", "app=e2e-signed-app", 10)).toBe(false);
    expect(getReplicaSetEvents("e2e-sbom-deny").toLowerCase()).toMatch(
      /policy enforcement failed|denied|sbom/i,
    );
  });

  it("admits pods with the skip annotation despite enforce mode", { timeout: 30000 }, () => {
    expect(podIsRunning("e2e-skip", "app=e2e-skip-app")).toBe(true);
  });

  it("rejects a duplicate SignatureEnforcement for the same namespace", { timeout: 10000 }, () => {
    const result = kubectl(`apply -f ${CRS_DUP}/sig-dup-second.yaml`, true);
    expect(result.toLowerCase()).toMatch(/already exists for namespace|denied/i);
  });

  it("rejects a duplicate SBOMEnforcement for the same namespace", { timeout: 10000 }, () => {
    const result = kubectl(`apply -f ${CRS_DUP}/sbom-dup-second.yaml`, true);
    expect(result.toLowerCase()).toMatch(/already exists for namespace|denied/i);
  });
});
