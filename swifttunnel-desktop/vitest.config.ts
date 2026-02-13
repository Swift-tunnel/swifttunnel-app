import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: [resolve(__dirname, "vitest.setup.ts")],
    clearMocks: true,
    restoreMocks: true,
    mockReset: true,
  },
});

