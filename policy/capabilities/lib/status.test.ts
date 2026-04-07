import { describe, it, expect } from "vitest";
import { shouldUpdateStatus, buildReadyStatus } from "./status.js";
import { StatusEnum } from "../generated/sbomenforcement-v1alpha1.js";

describe("shouldUpdateStatus", () => {
  it("returns true when generations differ", () => {
    expect(shouldUpdateStatus(2, 1)).toBe(true);
  });

  it("returns false when generations match", () => {
    expect(shouldUpdateStatus(3, 3)).toBe(false);
  });

  it("returns false when both are undefined (new resource, no status yet treated as 0===0)", () => {
    expect(shouldUpdateStatus(undefined, undefined)).toBe(false);
  });

  it("returns true when generation is set but observedGeneration is undefined", () => {
    expect(shouldUpdateStatus(1, undefined)).toBe(true);
  });

  it("returns true when generation is undefined but observedGeneration is set", () => {
    expect(shouldUpdateStatus(undefined, 1)).toBe(true);
  });
});

describe("buildReadyStatus", () => {
  const fixedDate = new Date("2025-01-15T12:00:00Z");

  it("sets observedGeneration to the given generation", () => {
    const status = buildReadyStatus(5, fixedDate);
    expect(status.observedGeneration).toBe(5);
  });

  it("produces a single Ready=True condition", () => {
    const status = buildReadyStatus(3, fixedDate);
    expect(status.conditions).toHaveLength(1);

    const cond = status.conditions![0];
    expect(cond.type).toBe("Ready");
    expect(cond.status).toBe(StatusEnum.True);
    expect(cond.reason).toBe("PolicyAccepted");
    expect(cond.lastTransitionTime).toEqual(fixedDate);
    expect(cond.observedGeneration).toBe(3);
  });

  it("defaults to current time when now is omitted", () => {
    const before = new Date();
    const status = buildReadyStatus(1);
    const after = new Date();

    const ts = status.conditions![0].lastTransitionTime as Date;
    expect(ts.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(ts.getTime()).toBeLessThanOrEqual(after.getTime());
  });
});
