import { useEffect, useState } from "react";
import { Button, Dialog, ErrorBanner, Toggle } from "../ui";
import { gamesDatacenters, gamesSetPreferences } from "../../lib/commands";
import { defaultGamePreferences } from "../../lib/gameLaunchFlow";
import { formatErrorMessage } from "../../lib/errors";
import type { GamePreferences, RobloxDatacenter, RobloxGameEntry, RobloxSettingsConfig } from "../../lib/types";

export function GamePreferencesDialog({ entry, onClose, onSaved }: { entry: RobloxGameEntry | null; onClose: () => void; onSaved: () => void }) {
  const [preferences, setPreferences] = useState<GamePreferences>({ datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false });
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [catalogError, setCatalogError] = useState(false);
  useEffect(() => {
    if (!entry) return;
    let disposed = false;
    setPreferences(defaultGamePreferences(entry)); setError(null); setCenters([]); setCatalogError(false);
    void gamesDatacenters().then(rows => { if (!disposed) setCenters(rows); }).catch(() => { if (!disposed) setCatalogError(true); });
    return () => { disposed = true; };
  }, [entry]);
  async function save() {
    if (!entry) return;
    setBusy(true); setError(null);
    try { await gamesSetPreferences(entry.place_id, entry.client, preferences); onSaved(); onClose(); }
    catch (error) { setError(formatErrorMessage(error)); }
    finally { setBusy(false); }
  }
  const patch = (value: Partial<GamePreferences>) => setPreferences(prev => ({ ...prev, ...value }));
  const field = "mt-2 w-full rounded-lg border border-border-subtle bg-bg-base px-3 py-2.5 text-sm text-text-primary";
  return <Dialog open={!!entry} onClose={() => { if (!busy) onClose(); }} title={`Settings for ${entry?.name ?? "this game"}`} description="A small profile for this game. FPS and graphics changes are restored when Roblox closes.">
    <div className="space-y-5 p-5 text-xs text-text-secondary">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {catalogError && <p className="text-text-muted">Locations could not load. FPS and graphics can still be changed; keep or clear your saved location and try again later.</p>}
      <label className="block">Preferred datacenter<select aria-label="Preferred datacenter" className={field} value={preferences.datacenter_id ?? ""}
        disabled={busy || entry?.client === "vng"} onChange={e => patch({ datacenter_id: e.target.value ? Number(e.target.value) : null })}>
        <option value="">Roblox matchmaking</option>
        {preferences.datacenter_id && !centers.some(c => c.id === preferences.datacenter_id) && <option value={preferences.datacenter_id}>Saved location unavailable</option>}
        {centers.map(c => <option key={c.id} value={c.id}>{c.city}, {c.country}</option>)}
      </select></label>
      <div className="grid grid-cols-2 gap-4">
        <label>Frame-rate cap<select aria-label="Game frame-rate cap" className={field} value={preferences.fps_cap ?? ""} disabled={busy} onChange={e => patch({ fps_cap: e.target.value ? Number(e.target.value) : null })}>
          <option value="">Use global cap</option>{[60, 120, 144, 165, 240, 300, 360, 480, 99999].map(fps => <option key={fps} value={fps}>{fps === 99999 ? "Uncapped" : `${fps} FPS`}</option>)}
          {preferences.fps_cap != null && ![60,120,144,165,240,300,360,480,99999].includes(preferences.fps_cap) && <option value={preferences.fps_cap}>{preferences.fps_cap} FPS</option>}
        </select></label>
        <label>Graphics level<select aria-label="Game graphics level" className={field} value={preferences.graphics_quality ?? ""} disabled={busy}
          onChange={e => patch({ graphics_quality: (e.target.value || null) as RobloxSettingsConfig["graphics_quality"] | null })}>
          <option value="">Use global graphics</option><option value="Automatic">Automatic</option>{Array.from({ length: 10 }, (_,i) => <option key={i} value={`Level${i + 1}`}>Level {i + 1}</option>)}
        </select></label>
      </div>
      <div className="flex items-start justify-between gap-4 rounded-xl border border-border-subtle p-4">
        <div><p className="font-semibold text-text-primary">Connect SwiftTunnel before playing</p><p className="mt-1.5 leading-relaxed text-text-muted">Uses the matching relay region when available. A connection started for this launch stops after the game ends. An existing manual connection stays on.</p></div>
        <Toggle enabled={preferences.use_tunnel} disabled={busy} ariaLabel="Connect SwiftTunnel before playing" onChange={use_tunnel => patch({ use_tunnel })} />
      </div>
      {entry?.client === "vng" && <p className="text-text-muted">VNG opens its official game page. Native region joining remains unavailable.</p>}
    </div>
    <div className="flex justify-end gap-2 border-t border-border-subtle p-4"><Button variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button><Button loading={busy} onClick={() => void save()}>Save profile</Button></div>
  </Dialog>;
}
