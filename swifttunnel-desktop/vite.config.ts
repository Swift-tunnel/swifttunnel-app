import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig(({ command }) => {
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
            "@tauri-apps/plugin-notification": path.resolve(__dirname, "src/mocks/tauri-plugin-notification.ts"),
          },
        }
      : {},
  };
});
