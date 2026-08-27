import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig(({ command, mode }) => {
  const isTauriRuntime =
    !!process.env.TAURI_ENV_PLATFORM ||
    !!process.env.TAURI_PLATFORM ||
    !!process.env.TAURI_ARCH;

  // Mocks are only for plain browser `vite dev`, never for packaged builds.
  const useBrowserMocks = command === "serve" && !isTauriRuntime;

  return {
    plugins: [react(), tailwindcss()],
    clearScreen: false,
    server: {
      port: 1420,
      strictPort: true,
      host: "localhost",
    },
    envPrefix: ["VITE_", "TAURI_"],
    build:
      mode === "lite"
        ? {
            rollupOptions: {
              treeshake: {
                /**
                 * Lite drops most of the app, and Rollup would not let it.
                 *
                 * A module stays in the bundle if Rollup cannot prove its
                 * top-level statements are free of side effects, even when
                 * nothing imports it any more. Statements as ordinary as a
                 * module-scope `.map()` or `new Map()` count, and those alone
                 * kept the Home page and the whole 33KB optimization catalog
                 * in a build that renders neither.
                 *
                 * Nothing under src/ is imported for its side effects (there
                 * is not one bare `import "./x"` outside CSS), so this says
                 * so. Scoped to Lite: the full app renders all of it anyway,
                 * so it would gain nothing there and is not worth the risk of
                 * the claim turning out to be wrong.
                 */
                moduleSideEffects: (id) => !/[\\/]src[\\/].*\.tsx?$/.test(id),
              },
            },
          }
        : {},

    define: {
      __APP_VERSION__: JSON.stringify(process.env.npm_package_version || "0.1.0"),
    },
    resolve: useBrowserMocks
      ? {
          alias: {
            "@tauri-apps/api/core": path.resolve(__dirname, "src/mocks/tauri-core.ts"),
            "@tauri-apps/api/event": path.resolve(__dirname, "src/mocks/tauri-event.ts"),
            "@tauri-apps/api/window": path.resolve(__dirname, "src/mocks/tauri-window.ts"),
            "@tauri-apps/api/dpi": path.resolve(__dirname, "src/mocks/tauri-dpi.ts"),
            "@tauri-apps/plugin-shell": path.resolve(__dirname, "src/mocks/tauri-plugin-shell.ts"),
            "@tauri-apps/plugin-updater": path.resolve(__dirname, "src/mocks/tauri-plugin-updater.ts"),
          },
        }
      : {},
  };
});
