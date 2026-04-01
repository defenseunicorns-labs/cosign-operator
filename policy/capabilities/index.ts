import { Capability } from "pepr";

export const imageSignature = new Capability({
  name: "image-signature-verification",
  description:
    "Validates that container images have valid cosign signatures from a trusted key.",
});

export const { When } = imageSignature;
