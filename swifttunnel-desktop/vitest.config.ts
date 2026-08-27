import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: [resolve(__dirname, "vitest.setup.ts")],
    // Run test files one at a time.
    //
    // In parallel the suite fails differently on every run: 6 tests, then 8,
    // then 4, across different files. Sequentially it passes 240/240 every
    // time. Isolation is already on by default, so this is not shared state,
    // it is assertions racing async work that the test never awaited, and
    // parallel files starve each other of CPU until the race is lost.
    //
    // This makes the result trustworthy today. The real fix is to find the
    // tests that assert without awaiting, and this comment should go with
    // them.
    fileParallelism: false,

    clearMocks: true,
    restoreMocks: true,
    mockReset: true,
  },
});

