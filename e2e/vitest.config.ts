import { defineConfig } from "vitest/config";
import { join } from "path";

export default defineConfig({
  test: {
    root: join(import.meta.dirname, ".."),
    include: ["e2e/**/*.test.ts"],
    testTimeout: 720_000,
    hookTimeout: 840_000,
    sequence: { concurrent: false },
  },
});
