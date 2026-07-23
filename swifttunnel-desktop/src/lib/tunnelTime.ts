// Persistent "total time tunneled" counter, accumulated globally (see App.tsx)
// and surfaced on the Home dashboard. Flushed incrementally so an app close
// mid-session loses at most one flush interval.

const KEY = "st.totalTunneledMs";

export function getTotalTunneledMs(): number {
  try {
    const v = Number(localStorage.getItem(KEY));
    return Number.isFinite(v) && v > 0 ? v : 0;
  } catch {
    return 0;
  }
}

export function addTunneledMs(ms: number): void {
  if (!(ms > 0)) return;
  try {
    localStorage.setItem(KEY, String(getTotalTunneledMs() + ms));
  } catch {
    // best-effort; the stat just won't grow this interval
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
