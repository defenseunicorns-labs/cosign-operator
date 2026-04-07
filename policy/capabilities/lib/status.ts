import {
  type StatusObject,
  StatusEnum,
} from "../generated/sbomenforcement-v1alpha1.js";

/** Returns true if the controller has not yet processed the current generation. */
export function shouldUpdateStatus(
  generation: number | undefined,
  observedGeneration: number | undefined,
): boolean {
  return (generation ?? 0) !== (observedGeneration ?? 0);
}

/** Build a Ready status for a successfully reconciled enforcement CR. */
export function buildReadyStatus(
  generation: number,
  now = new Date(),
): StatusObject {
  return {
    observedGeneration: generation,
    conditions: [
      {
        type: "Ready",
        status: StatusEnum.True,
        reason: "PolicyAccepted",
        message: "Policy has been accepted by the controller",
        lastTransitionTime: now,
        observedGeneration: generation,
      },
    ],
  };
}
