// Lifetime "time tunneled" counter, accumulated globally (see App.tsx) and
// surfaced on the Home dashboard.
//
// Kept in the settings file rather than the webview's localStorage, because
// each Tauri app gets its own webview data directory keyed by bundle
// identifier. A browser-side counter forks into two the moment somebody
// installs both the full app and Lite, and the two never reconcile.

import { useSettingsStore } from "../stores/settingsStore";

/** Where the counter used to live. Read once, to carry existing users over. */
const LEGACY_KEY = "st.totalTunneledMs";

function legacyValue(): number {
  try {
    const raw = Number(localStorage.getItem(LEGACY_KEY));
    return Number.isFinite(raw) && raw > 0 ? raw : 0;
  } catch {
    return 0;
  }
}

function clearLegacy(): void {
  try {
    localStorage.removeItem(LEGACY_KEY);
  } catch {
    // Nothing to do: the worst case is the migration runs again and the
    // Math.max below keeps it idempotent.
  }
}

export function getTotalTunneledMs(): number {
  const stored = useSettingsStore.getState().settings.total_tunneled_ms;
  const current = Number.isFinite(stored) && stored > 0 ? stored : 0;

  // Whichever is larger wins, so an install that predates the move keeps its
  // total and a fresh one is unaffected. Both paths converge on the first add.
  return Math.max(current, legacyValue());
}

export function addTunneledMs(ms: number): void {
  if (!(ms > 0)) return;

  const total = getTotalTunneledMs() + ms;
  const store = useSettingsStore.getState();
  store.update({ total_tunneled_ms: total });
  void store.save();

  // Only once the new home has the value, so an interrupted migration cannot
  // lose the old total.
  if (legacyValue() > 0) {
    clearLegacy();
  }
}

/** Compact human duration: "3d 5h", "12h 34m", "45m", "12s". */
export function formatDuration(ms: number): string {
  const totalSec = Math.floor(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const totalMin = Math.floor(totalSec / 60);
  const d = Math.floor(totalMin / 1440);
  const h = Math.floor((totalMin % 1440) / 60);
  const m = totalMin % 60;
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
