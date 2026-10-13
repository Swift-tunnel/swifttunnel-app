import { useEffect, useState } from "react";
import { Button, Dialog, ErrorBanner, Field, Select, Toggle } from "../ui";
import { gamesDatacenters, gamesSetPreferences, gamesLauncherConfig, gamesDisplays } from "../../lib/commands";
import { defaultGamePreferences } from "../../lib/gameLaunchFlow";
import { formatErrorMessage } from "../../lib/errors";
import type { GamePreferences, RobloxDatacenter, RobloxGameEntry, RobloxSettingsConfig, GameDisplay } from "../../lib/types";

export function GamePreferencesDialog({ entry, onClose, onSaved }: { entry: RobloxGameEntry | null; onClose: () => void; onSaved: () => void }) {
  const [preferences, setPreferences] = useState<GamePreferences>({ datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false });
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [catalogError, setCatalogError] = useState(false);
  const [profiles,setProfiles]=useState<string[]>([]);
  const [displays,setDisplays]=useState<GameDisplay[]>([]);
  useEffect(() => {
    if (!entry) return;
    let disposed = false;
    setPreferences(defaultGamePreferences(entry)); setError(null); setCenters([]); setCatalogError(false);
    void gamesDatacenters().then(rows => { if (!disposed) setCenters(rows); }).catch(() => { if (!disposed) setCatalogError(true); });
    void gamesLauncherConfig().then(c=>{if(!disposed)setProfiles(c.profiles.map(p=>p.name));}).catch(()=>{});
    void gamesDisplays().then(rows=>{if(!disposed)setDisplays(rows);}).catch(()=>{});
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
  return <Dialog open={!!entry} onClose={() => { if (!busy) onClose(); }} title={`Settings for ${entry?.name ?? "this game"}`} description="Your settings for this game. Temporary FPS, graphics and FastFlags restore after Roblox closes.">
    <div className="flex flex-col gap-4">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {catalogError && <p className="text-[11.5px] leading-relaxed text-text-muted">Locations could not load. FPS and graphics can still be changed; keep or clear your saved location and try again later.</p>}
      <Field label="Preferred datacenter"><Select block aria-label="Preferred datacenter" value={preferences.datacenter_id ?? ""}
        disabled={busy || entry?.client === "vng"} onChange={e => patch({ datacenter_id: e.target.value ? Number(e.target.value) : null })}>
        <option value="">Default matchmaking</option>
        {preferences.datacenter_id && !centers.some(c => c.id === preferences.datacenter_id) && <option value={preferences.datacenter_id}>Saved location unavailable</option>}
        {centers.map(c => <option key={c.id} value={c.id}>{c.city}, {c.country}</option>)}
      </Select></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Named settings profile"><Select block value={preferences.flag_profile??""} aria-label="Named game profile" onChange={e=>patch({flag_profile:e.target.value||null})}><option value="">Global SwiftTunnel settings</option>{preferences.flag_profile&&!profiles.includes(preferences.flag_profile)&&<option value={preferences.flag_profile}>Missing: {preferences.flag_profile}</option>}{profiles.map(p=><option key={p} value={p}>{p}</option>)}</Select></Field>
        <Field label="Matchmaking"><Select block value={preferences.skip_matchmaker?"skip":"inherit"} aria-label="Game Matchmaker preference" onChange={e=>patch({skip_matchmaker:e.target.value==="skip"})}><option value="inherit">Use Matchmaker preference</option><option value="skip">Skip Matchmaker</option></Select></Field>
        <Field label="Frame-rate cap"><Select block aria-label="Game frame-rate cap" value={preferences.fps_cap ?? ""} disabled={busy} onChange={e => patch({ fps_cap: e.target.value ? Number(e.target.value) : null })}>
          <option value="">{preferences.flag_profile?"Use profile cap":"Use global cap"}</option>{[60, 120, 144, 165, 240, 300, 360, 480, 99999].map(fps => <option key={fps} value={fps}>{fps === 99999 ? "Uncapped" : `${fps} FPS`}</option>)}
          {preferences.fps_cap != null && ![60,120,144,165,240,300,360,480,99999].includes(preferences.fps_cap) && <option value={preferences.fps_cap}>{preferences.fps_cap} FPS</option>}
        </Select></Field>
        <Field label="Graphics level"><Select block aria-label="Game graphics level" value={preferences.graphics_quality ?? ""} disabled={busy}
          onChange={e => patch({ graphics_quality: (e.target.value || null) as RobloxSettingsConfig["graphics_quality"] | null })}>
          <option value="">{preferences.flag_profile?"Use profile graphics":"Use global graphics"}</option><option value="Automatic">Automatic</option>{Array.from({ length: 10 }, (_,i) => <option key={i} value={`Level${i + 1}`}>Level {i + 1}</option>)}
        </Select></Field>
      </div>
      <div className="grid grid-cols-2 gap-3"><Field label="Window mode"><Select block aria-label="Game window mode" value={preferences.borderless?"borderless":"default"} onChange={e=>patch({borderless:e.target.value==="borderless"})}><option value="default">Roblox default</option><option value="borderless">Borderless</option></Select></Field><Field label="Monitor"><Select block aria-label="Game monitor" value={preferences.monitor??""} onChange={e=>patch({monitor:e.target.value||null})}><option value="">Roblox default</option>{preferences.monitor&&!displays.some(d=>d.id===preferences.monitor)&&<option value={preferences.monitor}>Saved display unavailable (uses primary)</option>}{displays.map((d,i)=><option key={d.id} value={d.id}>Display {i+1}{d.primary?" · Primary":""} · {d.width}×{d.height}</option>)}</Select></Field></div>
      <div className="flex items-center justify-between gap-4 rounded-[10px] bg-bg-base px-3.5 py-3">
        <div className="min-w-0"><p className="text-[12.5px] font-medium leading-tight text-text-primary">Connect SwiftTunnel before playing</p><p className="mt-1 text-[11px] leading-snug text-text-muted">Uses the matching relay region when available. A connection started for this launch stops after the game ends. An existing manual connection stays on.</p></div>
        <Toggle enabled={preferences.use_tunnel} disabled={busy} ariaLabel="Connect SwiftTunnel before playing" onChange={use_tunnel => patch({ use_tunnel })} />
      </div>
      {entry?.client === "vng" && <p className="text-[11.5px] leading-relaxed text-text-muted">VNG opens its official game page. Native region joining remains unavailable.</p>}
      <div className="flex justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy} onClick={onClose}>Cancel</Button><Button size="sm" loading={busy} onClick={() => void save()}>Save profile</Button></div>
    </div>
  </Dialog>;
}
