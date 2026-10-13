import { useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, ErrorBanner, Segmented, Select, SliderInput, Toggle } from "../ui";
import { gamesDatacenters, gamesSetPreferences, gamesLauncherConfig, gamesDisplays } from "../../lib/commands";
import { defaultGamePreferences } from "../../lib/gameLaunchFlow";
import { formatErrorMessage } from "../../lib/errors";
import { useSettingsStore } from "../../stores/settingsStore";
import type { GamePreferences, RobloxDatacenter, RobloxGameEntry, RobloxSettingsConfig, GameDisplay } from "../../lib/types";

function Group({ title, children }: { title: string; children: ReactNode }) {
  return <section><p className="eyebrow mb-1.5 px-0.5">{title}</p><div className="divide-y divide-border-subtle rounded-[10px] bg-bg-base">{children}</div></section>;
}
/** One setting: its name on the left, its control on the right, and room underneath for a slider or a set of choices. */
function Setting({ label, desc, children, below }: { label: string; desc?: string; children?: ReactNode; below?: ReactNode }) {
  return <div className="px-3.5 py-2.5">
    <div className="flex min-h-[30px] items-center justify-between gap-4">
      <div className="min-w-0"><p className="text-[12.5px] font-medium leading-tight text-text-primary">{label}</p>{desc && <p className="mt-[3px] text-[11px] leading-snug text-text-muted">{desc}</p>}</div>
      {children && <div className="shrink-0">{children}</div>}
    </div>
    {below && <div className="mt-2.5">{below}</div>}
  </div>;
}

export function GamePreferencesDialog({ entry, onClose, onSaved }: { entry: RobloxGameEntry | null; onClose: () => void; onSaved: () => void }) {
  const [preferences, setPreferences] = useState<GamePreferences>({ datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false });
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [catalogError, setCatalogError] = useState(false);
  const [profiles,setProfiles]=useState<string[]>([]);
  const [displays,setDisplays]=useState<GameDisplay[]>([]);
  const globalFps = useSettingsStore(s => s.settings.config.roblox_settings.target_fps);
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

  // "Global" follows the app-wide Roblox settings, or the chosen profile when the game has one.
  const inherit = preferences.flag_profile ? "Profile" : "Global";
  const fps = preferences.fps_cap;
  const fpsMode = fps == null ? "inherit" : fps >= 9999 ? "uncapped" : "custom";
  const quality = preferences.graphics_quality;
  const qualityMode = quality == null ? "inherit" : quality === "Automatic" ? "auto" : "manual";
  const level = quality && quality.startsWith("Level") ? Number(quality.slice(5)) : 5;
  const monitors = [
    { id: "", label: "Roblox default", detail: "" },
    ...displays.map((d, i) => ({ id: d.id, label: `Display ${i + 1}`, detail: `${d.width}×${d.height}${d.primary ? " · Primary" : ""}` })),
    ...(preferences.monitor && !displays.some(d => d.id === preferences.monitor) ? [{ id: preferences.monitor, label: "Saved display", detail: "Unavailable, uses primary" }] : []),
  ];

  return <Dialog flush maxWidth={520} open={!!entry} onClose={() => { if (!busy) onClose(); }} title={`Settings for ${entry?.name ?? "this game"}`} description="Only for this game. FPS, graphics and FastFlags go back to normal when Roblox closes.">
    <div className="flex max-h-[calc(100vh-13rem)] flex-col gap-4 overflow-y-auto px-5 py-4">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {catalogError && <p className="text-[11.5px] leading-relaxed text-text-muted">Locations could not load. Everything else can still be changed.</p>}
      <Group title="Server">
        <Setting label="Preferred location">
          <Select width={210} aria-label="Preferred datacenter" value={preferences.datacenter_id ?? ""}
            disabled={busy || entry?.client === "vng"} onChange={e => patch({ datacenter_id: e.target.value ? Number(e.target.value) : null })}>
            <option value="">Default matchmaking</option>
            {preferences.datacenter_id && !centers.some(c => c.id === preferences.datacenter_id) && <option value={preferences.datacenter_id}>Saved location unavailable</option>}
            {centers.map(c => <option key={c.id} value={c.id}>{c.city}, {c.country}</option>)}
          </Select>
        </Setting>
        <Setting label="Skip Matchmaker" desc="Always let Roblox pick the server for this game.">
          <Toggle enabled={!!preferences.skip_matchmaker} disabled={busy} ariaLabel="Skip Matchmaker for this game" onChange={skip_matchmaker => patch({ skip_matchmaker })} />
        </Setting>
        <Setting label="Connect SwiftTunnel before playing" desc="Uses the matching relay and disconnects when the game ends.">
          <Toggle enabled={preferences.use_tunnel} disabled={busy} ariaLabel="Connect SwiftTunnel before playing" onChange={use_tunnel => patch({ use_tunnel })} />
        </Setting>
      </Group>
      <Group title="Performance">
        {(profiles.length > 0 || preferences.flag_profile) && <Setting label="Settings profile">
          <Select width={210} value={preferences.flag_profile??""} aria-label="Named game profile" disabled={busy} onChange={e=>patch({flag_profile:e.target.value||null})}><option value="">Global settings</option>{preferences.flag_profile&&!profiles.includes(preferences.flag_profile)&&<option value={preferences.flag_profile}>Missing: {preferences.flag_profile}</option>}{profiles.map(p=><option key={p} value={p}>{p}</option>)}</Select>
        </Setting>}
        <Setting label="Frame-rate cap" below={fpsMode === "custom" && <div className="flex justify-end"><SliderInput ariaLabel="Game frame-rate cap" value={fps ?? 144} min={30} max={1000} step={10} unit="FPS" width={230} disabled={busy} onChange={fps_cap => patch({ fps_cap })} /></div>}>
          <Segmented ariaLabel="Frame-rate cap" disabled={busy} value={fpsMode} options={[{ value: "inherit", label: inherit }, { value: "custom", label: "Custom" }, { value: "uncapped", label: "Uncapped" }]}
            onChange={mode => patch({ fps_cap: mode === "inherit" ? null : mode === "uncapped" ? 99999 : Math.max(30, Math.min(1000, globalFps < 9999 ? globalFps : 144)) })} />
        </Setting>
        <Setting label="Graphics" below={qualityMode === "manual" && <div className="flex justify-end"><SliderInput ariaLabel="Game graphics level" value={level} min={1} max={10} unit="of 10" width={230} disabled={busy} onChange={next => patch({ graphics_quality: `Level${next}` as RobloxSettingsConfig["graphics_quality"] })} /></div>}>
          <Segmented ariaLabel="Graphics" disabled={busy} value={qualityMode} options={[{ value: "inherit", label: inherit }, { value: "auto", label: "Automatic" }, { value: "manual", label: "Manual" }]}
            onChange={mode => patch({ graphics_quality: (mode === "inherit" ? null : mode === "auto" ? "Automatic" : `Level${level}`) as RobloxSettingsConfig["graphics_quality"] | null })} />
        </Setting>
      </Group>
      <Group title="Window">
        <Setting label="Borderless window">
          <Toggle enabled={!!preferences.borderless} disabled={busy} ariaLabel="Borderless window" onChange={borderless => patch({ borderless })} />
        </Setting>
        <Setting label="Monitor" below={<div role="group" aria-label="Game monitor" className="flex flex-wrap gap-1.5">{monitors.map(m => {
          const active = (preferences.monitor ?? "") === m.id;
          return <button key={m.id} type="button" aria-pressed={active} disabled={busy} onClick={() => patch({ monitor: m.id || null })}
            className={`rounded-[var(--radius-button)] border px-3 py-1.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${active ? "border-border-strong bg-bg-active" : "border-border-subtle hover:bg-bg-hover"}`}>
            <span className={`block text-[11.5px] font-medium leading-tight ${active ? "text-text-primary" : "text-text-secondary"}`}>{m.label}</span>
            {m.detail && <span className="mt-0.5 block font-mono text-[10px] leading-tight text-text-dimmed">{m.detail}</span>}
          </button>;
        })}</div>} />
      </Group>
      {entry?.client === "vng" && <p className="text-[11.5px] leading-relaxed text-text-muted">VNG opens its official game page, so a preferred location does not apply.</p>}
    </div>
    <div className="flex justify-end gap-2 border-t border-border-subtle px-5 py-3"><Button size="sm" variant="secondary" disabled={busy} onClick={onClose}>Cancel</Button><Button size="sm" loading={busy} onClick={() => void save()}>Save</Button></div>
  </Dialog>;
}
