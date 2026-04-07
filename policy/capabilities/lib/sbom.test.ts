import { describe, it, expect } from "vitest";
import { parseSbomDocument, checkDeniedComponents } from "./sbom.js";

describe("parseSbomDocument", () => {
  it("parses CycloneDX components", () => {
    const doc = {
      components: [
        { name: "log4j-core", version: "2.14.1" },
        { name: "spring-boot", version: "3.1.0" },
      ],
    };
    expect(parseSbomDocument(doc)).toEqual([
      { name: "log4j-core", version: "2.14.1" },
      { name: "spring-boot", version: "3.1.0" },
    ]);
  });

  it("parses SPDX packages", () => {
    const doc = {
      packages: [
        { name: "log4j-core", versionInfo: "2.14.1" },
        { name: "spring-boot", versionInfo: "3.1.0" },
      ],
    };
    expect(parseSbomDocument(doc)).toEqual([
      { name: "log4j-core", version: "2.14.1" },
      { name: "spring-boot", version: "3.1.0" },
    ]);
  });

  it("defaults missing version to empty string", () => {
    const doc = { components: [{ name: "foo" }] };
    expect(parseSbomDocument(doc)).toEqual([{ name: "foo", version: "" }]);
  });

  it("skips entries without a name", () => {
    const doc = { components: [{ version: "1.0.0" }, { name: "bar", version: "2.0.0" }] };
    expect(parseSbomDocument(doc)).toEqual([{ name: "bar", version: "2.0.0" }]);
  });

  it("returns empty array for unknown format", () => {
    expect(parseSbomDocument({ something: "else" })).toEqual([]);
  });
});

describe("checkDeniedComponents", () => {
  it("returns empty when no components match", () => {
    const components = [{ name: "safe-lib", version: "1.0.0" }];
    const denied = [{ name: "log4j-core", versionRange: "*" }];
    expect(checkDeniedComponents(components, denied)).toEqual([]);
  });

  it("matches wildcard version range", () => {
    const components = [{ name: "log4j-core", version: "2.14.1" }];
    const denied = [{ name: "log4j-core", versionRange: "*" }];
    const result = checkDeniedComponents(components, denied);
    expect(result).toHaveLength(1);
    expect(result[0]).toContain("log4j-core@2.14.1");
    expect(result[0]).toContain("all versions");
  });

  it("matches semver range", () => {
    const components = [{ name: "log4j-core", version: "2.14.1" }];
    const denied = [{ name: "log4j-core", versionRange: "<2.17.0" }];
    const result = checkDeniedComponents(components, denied);
    expect(result).toHaveLength(1);
    expect(result[0]).toContain("matches <2.17.0");
  });

  it("does not match when version is outside range", () => {
    const components = [{ name: "log4j-core", version: "2.17.1" }];
    const denied = [{ name: "log4j-core", versionRange: "<2.17.0" }];
    expect(checkDeniedComponents(components, denied)).toEqual([]);
  });

  it("falls back to exact match for non-semver ranges", () => {
    const components = [{ name: "bad-lib", version: "abc123" }];
    const denied = [{ name: "bad-lib", versionRange: "abc123" }];
    const result = checkDeniedComponents(components, denied);
    expect(result).toHaveLength(1);
    expect(result[0]).toContain("exact match");
  });

  it("does not match different names", () => {
    const components = [{ name: "good-lib", version: "2.14.1" }];
    const denied = [{ name: "log4j-core", versionRange: "*" }];
    expect(checkDeniedComponents(components, denied)).toEqual([]);
  });

  it("reports multiple violations", () => {
    const components = [
      { name: "log4j-core", version: "2.14.1" },
      { name: "struts", version: "1.3.10" },
    ];
    const denied = [
      { name: "log4j-core", versionRange: "<2.17.0" },
      { name: "struts", versionRange: "*" },
    ];
    expect(checkDeniedComponents(components, denied)).toHaveLength(2);
  });
});
