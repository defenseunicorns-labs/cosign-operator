import { PeprModule } from "pepr";
import { imageSignature } from "./capabilities/index.js";
import "./capabilities/verify.js";
import { readFileSync } from "fs";

const cfg = JSON.parse(
  readFileSync("./package.json", "utf-8"),
);

new PeprModule(cfg, [imageSignature]);
