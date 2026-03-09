import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { reportError } from "./errors";

let checkedPermission = false;
let allowed = false;

async function ensurePermission(): Promise<boolean> {
  if (checkedPermission) return allowed;

  try {
    allowed = await isPermissionGranted();
    if (!allowed) {
      const permission = await requestPermission();
      allowed = permission === "granted";
    }
  } catch (error) {
    reportError("Notification permission check failed", error, {
      dedupeKey: "notifications-permission",
    });
    allowed = false;
  } finally {
    checkedPermission = true;
  }

  return allowed;
}

export async function notify(title: string, body?: string) {
  const permitted = await ensurePermission();
  if (!permitted) return;
  sendNotification({ title, body });
}
