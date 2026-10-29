import { NAV_ITEMS } from "../components/shell/nav";
import type { TabId } from "./types";

type ShortcutEvent = Pick<KeyboardEvent,
  "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey" | "repeat" |
  "isComposing" | "defaultPrevented" | "target" | "preventDefault"
>;

export function handleTabShortcut(event: ShortcutEvent, navigate: (tab: TabId) => void): void {
  if (event.defaultPrevented || event.repeat || event.isComposing ||
      !(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
  const target = event.target as Element | null;
  // Include nested editable elements and custom text/dropdown controls.
  if (typeof target?.closest === "function" && target.closest(
    "input, textarea, select, [contenteditable]:not([contenteditable='false']), [role='textbox'], [role='combobox']",
  )) return;
  const item = NAV_ITEMS.find(item => item.shortcut === event.key);
  if (!item) return;
  event.preventDefault();
  navigate(item.id);
}
