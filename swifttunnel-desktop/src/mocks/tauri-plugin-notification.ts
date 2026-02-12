// Mock @tauri-apps/plugin-notification for browser preview

export async function isPermissionGranted() {
  return true;
}

export async function requestPermission() {
  return "granted" as const;
}

export function sendNotification(options: { title: string; body?: string }) {
  console.log(`[tauri-mock] notification: ${options.title} — ${options.body ?? ""}`);
}
