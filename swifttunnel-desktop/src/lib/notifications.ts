import { invoke } from "@tauri-apps/api/core";

export async function notify(title: string, body?: string) {
  try {
    await invoke("system_show_notification", { title, body: body ?? "" });
  } catch (e) {
    console.warn("Failed to show notification:", e);
  }
}
