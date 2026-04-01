import { PeprModule } from "pepr";
import cfg from "./package.json";
import { imageSignature } from "./capabilities/index.js";
import "./capabilities/verify.js";

new PeprModule(cfg, [imageSignature]);
