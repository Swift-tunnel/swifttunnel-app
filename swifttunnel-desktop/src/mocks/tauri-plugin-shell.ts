// Mock @tauri-apps/plugin-shell for browser preview

export async function open(url: string) {
  console.log(`[tauri-mock] shell.open: ${url}`);
  window.open(url, "_blank");
}
