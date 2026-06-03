import { describe, it, expect } from "vitest";
import { findMode, collectDeniedComponents } from "./policy.js";
import type { SBOMEnforcement } from "../generated/sbomenforcement-v1alpha1.js";

function sigPolicy(namespaces: string[], mode: string) {
  return { spec: { namespaces, enforcementPolicy: { mode } } };
}

function sbomPolicy(
  namespaces: string[],
  mode: string,
  denied: { name: string; versionRange: string }[] = [],
): SBOMEnforcement {
  return {
    spec: { namespaces, enforcementPolicy: { mode }, deniedComponents: denied },
  } as SBOMEnforcement;
}

describe("findMode", () => {
  it("returns null when no policies exist", () => {
    expect(findMode("default", {})).toBeNull();
  });

  it("returns null when no policy targets the namespace", () => {
    const configs = { a: sigPolicy(["other"], "enforce") };
    expect(findMode("default", configs)).toBeNull();
  });

  it("returns 'warn' when the matching policy is warn", () => {
    const configs = { a: sigPolicy(["default"], "warn") };
    expect(findMode("default", configs)).toBe("warn");
  });

  it("returns 'enforce' when the matching policy is enforce", () => {
    const configs = { a: sigPolicy(["default"], "enforce") };
    expect(findMode("default", configs)).toBe("enforce");
  });

  it("ignores policies targeting other namespaces", () => {
    const configs = {
      a: sigPolicy(["other"], "enforce"),
      b: sigPolicy(["default"], "warn"),
    };
    expect(findMode("default", configs)).toBe("warn");
  });

  it("handles policies with missing spec gracefully", () => {
    const configs = { a: {} as ReturnType<typeof sigPolicy> };
    expect(findMode("default", configs)).toBeNull();
  });
});

describe("collectDeniedComponents", () => {
  it("returns empty array when no policies exist", () => {
    expect(collectDeniedComponents("default", {})).toEqual([]);
  });

  it("returns empty array when no policy targets the namespace", () => {
    const configs = {
      a: sbomPolicy(["other"], "enforce", [{ name: "log4j", versionRange: "*" }]),
    };
    expect(collectDeniedComponents("default", configs)).toEqual([]);
  });

  it("collects denied components from the matching policy", () => {
    const configs = {
      a: sbomPolicy(["default"], "enforce", [
        { name: "log4j", versionRange: "<2.17.0" },
      ]),
      b: sbomPolicy(["other"], "enforce", [
        { name: "should-not-appear", versionRange: "*" },
      ]),
    };
    const result = collectDeniedComponents("default", configs);
    expect(result).toHaveLength(1);
    expect(result).toContainEqual({ name: "log4j", versionRange: "<2.17.0" });
  });
});
