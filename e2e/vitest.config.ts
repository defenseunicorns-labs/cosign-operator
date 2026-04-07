import { defineConfig } from "vitest/config";
import { join } from "path";

export default defineConfig({
  test: {
    root: join(import.meta.dirname, ".."),
    include: ["e2e/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 600_000,
    sequence: { concurrent: false },
  },
});
