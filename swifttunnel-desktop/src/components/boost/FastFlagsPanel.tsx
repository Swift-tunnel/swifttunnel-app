import { useState, type ReactNode } from "react";
import { Button, Dialog, ErrorBanner, Icon, Panel, Row, Slider, Toggle } from "../ui";
import { useSettingsStore } from "../../stores/settingsStore";
import { boostCloseRoblox, boostGetMetrics, gamesSaveFlags, systemOpenUrl } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { booleanFlag, FLAG_KEYS, flagBool, flagNumber, flagPreset, MESH_FLAGS, parseFlags, patchFlags, rendererPatch, RENDERER_FLAGS, validateCustomFflags, type FlagMap } from "../../lib/fastFlags";
import { NvidiaPanel } from "./NvidiaPanel";

const selectClass = "max-w-[180px] rounded-[var(--radius-button)] border border-border-default bg-bg-elevated px-2.5 py-1.5 text-[11px] text-text-primary outline-none focus-visible:border-border-focus disabled:opacity-40";
function FlagSection({ title, desc, children }: { title: string; desc: string; children: ReactNode }) {
  return <Panel eyebrow={title} desc={desc} flush watermark={{ icon: "settings", at: "right", size: 130, opacity: .025 }}>
    <div className="divide-y divide-border-subtle border-t border-border-subtle">{children}</div>
  </Panel>;
}
export function FastFlagsPanel() {
  const saved = useSettingsStore(s => s.settings.config.roblox_settings);
  const [baseline, setBaseline] = useState(saved);
  const [enabled, setEnabled] = useState(saved.custom_fflags_enabled);
  const [raw, setRaw] = useState(saved.custom_fflags_json || "{}");
  const [section, setSection] = useState<"roblox" | "advanced" | "nvidia">("roblox");
  const [nvidiaVisited,setNvidiaVisited] = useState(false);
  const [search, setSearch] = useState("");
  const [preset, setPreset] = useState<"default" | "balanced" | "performance">("balanced");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [closing, setClosing] = useState(false);
  const [reset, setReset] = useState(false);
  const [adding, setAdding] = useState(false);
  const [key, setKey] = useState<string>(FLAG_KEYS[0]);
  const [value, setValue] = useState("False");
  const [jsonView, setJsonView] = useState(false);
  const flags = parseFlags(raw);
  const rawError = validateCustomFflags(true, raw);
  const validation = validateCustomFflags(enabled, raw);
  const changed = enabled !== baseline.custom_fflags_enabled || raw !== (baseline.custom_fflags_json || "{}");
  const externalChange = saved.custom_fflags_enabled !== baseline.custom_fflags_enabled || saved.custom_fflags_json !== baseline.custom_fflags_json || saved.ultraboost !== baseline.ultraboost;
  const locked = busy || !enabled || !!rawError;
  function setFlags(next: FlagMap) { setRaw(JSON.stringify(next, null, 2)); setError(null); setNotice(null); }
  function patch(next: Record<string, string | number | boolean | null>) { setFlags(patchFlags(flags, next)); }
  function reload() { setBaseline(saved); setEnabled(saved.custom_fflags_enabled); setRaw(saved.custom_fflags_json || "{}"); setError(null); setNotice(null); }
  function toggleManage(next: boolean) {
    setEnabled(next); setNotice(null);
    if (next && !Object.keys(flags).length) setFlags(flagPreset("balanced"));
  }
  async function save(close = false) {
    if (validation || busy) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      if (close) await boostCloseRoblox();
      if ((await boostGetMetrics()).roblox_running) { setClosing(true); return; }
      const result = await gamesSaveFlags(enabled, raw, baseline);
      useSettingsStore.getState().update({ config: result.applied_config });
      setBaseline(result.applied_config.roblox_settings);
      setClosing(false);
      if (result.warnings.length) { setError(result.warnings.join("\n")); setNotice("Saved the configuration, with warnings. Review the files that could not be updated."); return; }
      setNotice(enabled ? "FastFlags saved and applied. They take effect on your next Roblox launch." : "Managed overrides removed. Roblox uses its defaults for these flags.");
    } catch (e) { setError(formatErrorMessage(e)); }
    finally { setBusy(false); }
  }
  const renderer = RENDERER_FLAGS.find(k => flagBool(flags, k)) ?? "default";
  const rows = Object.entries(flags).filter(([key]) => key.toLowerCase().includes(search.toLowerCase()));
  return <div className="space-y-4" data-search-anchor="custom_fflags">
    <Panel flush>
      <div className="flex flex-wrap items-center gap-1 p-2.5" role="tablist" aria-label="FastFlag editors">
        {([ ["roblox", "Roblox flags", "roblox"], ["advanced", "Advanced editor", "settings"], ["nvidia", "NVIDIA driver", "gpu"] ] as const).map(([id, label, icon]) => <button key={id} role="tab" aria-selected={section === id} aria-controls={`flags-${id}`} id={`flags-tab-${id}`} onClick={() => {setSection(id);if(id==="nvidia")setNvidiaVisited(true);}} className={`flex items-center gap-2 rounded-[var(--radius-button)] px-3 py-2 text-[11px] font-medium transition-colors focus-visible:outline focus-visible:outline-border-focus ${section === id ? "bg-bg-active text-text-primary" : "text-text-muted hover:bg-bg-hover"}`}><Icon name={icon} size={14} />{label}</button>)}
        <span className="ml-auto px-2 text-[10px] text-text-muted">{Object.keys(flags).length} overrides</span>
      </div>
    </Panel>
    {nvidiaVisited && <div hidden={section!=="nvidia"} role="tabpanel" id="flags-nvidia" aria-labelledby="flags-tab-nvidia"><NvidiaPanel /></div>}
    {section !== "nvidia" && <div role="tabpanel" id={`flags-${section}`} aria-labelledby={`flags-tab-${section}`} className="space-y-4">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <p role="status" className="rounded-lg border border-border-subtle bg-bg-card p-3 text-xs text-text-secondary">{notice}</p>}
      {externalChange && <ErrorBanner tone="warning">Saved settings changed elsewhere. <button className="underline" onClick={reload} disabled={busy}>Reload saved overrides</button> before saving this draft.</ErrorBanner>}
      <Panel flush watermark={{ icon: "roblox", at: "right", size: 140, opacity: .035 }}>
        <Row label="Manage FastFlags" desc="Turn off to remove the supported override set from Roblox." ><Toggle enabled={enabled} onChange={toggleManage} disabled={busy} ariaLabel="Manage FastFlags" /></Row>
        {baseline.ultraboost && <p className="px-3.5 pb-3 text-[11px] text-status-warning">Ultraboost currently controls these flags. Saving here replaces it with your editor selection.</p>}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border-subtle px-3.5 py-2.5"><Button variant="ghost" size="sm" onClick={() => setReset(true)} disabled={busy}>Reset overrides</Button><button onClick={() => void systemOpenUrl("https://devforum.roblox.com/t/allowlist-for-local-client-configuration-via-fast-flags/3966569").catch(e => setError(formatErrorMessage(e)))} className="text-[11px] text-text-muted underline underline-offset-4">Roblox's allowed flags ↗</button></div>
      </Panel>
      {validation && <ErrorBanner tone="warning">{validation} {section !== "advanced" && <button className="underline" onClick={() => setSection("advanced")}>Review in Advanced editor</button>}</ErrorBanner>}
      {section === "roblox" ? <>
        <FlagSection title="Grass & mesh detail" desc="Control movement and detail distances without changing your frame-rate cap.">
          <Row label="Grass movement" desc="Leave default to let Roblox decide."><select className={selectClass} aria-label="Grass movement" disabled={locked} value={flags.FIntGrassMovementReducedMotionFactor === undefined ? "default" : String(flags.FIntGrassMovementReducedMotionFactor)} onChange={e => patch({ FIntGrassMovementReducedMotionFactor: e.target.value === "default" ? null : Number(e.target.value) })}>{[ ["default", "Default movement"], ["0", "No movement"], ["1", "Minimal"], ["2", "Medium"], ["3", "High"], ["4", "Ultra"] ].map(([v,l]) => <option value={v} key={v}>{l}</option>)}</select></Row>
          <FlagSlider label="Mesh detail distance" desc="Override CSG mesh detail switching distances." enabled={MESH_FLAGS.some(k => flags[k] !== undefined)} value={flagNumber(flags, MESH_FLAGS[0], 250)} min={0} max={1000} step={25} unit="studs" disabled={locked} onToggle={v => patch(Object.fromEntries(MESH_FLAGS.map(k => [k, v ? 250 : null])))} onChange={v => patch(Object.fromEntries(MESH_FLAGS.map(k => [k, v])))} />
          <FlagSlider label="FRM quality override" desc="Override Roblox's automatic rendering quality, from 1 to 21." enabled={flags.DFIntDebugFRMQualityLevelOverride !== undefined} value={flagNumber(flags,"DFIntDebugFRMQualityLevelOverride",21)} min={1} max={21} disabled={locked} onToggle={v => patch({DFIntDebugFRMQualityLevelOverride:v?21:null})} onChange={v => patch({DFIntDebugFRMQualityLevelOverride:v})} />
        </FlagSection>
        <FlagSection title="Rendering & graphics" desc="Renderer changes take effect after Roblox closes and launches again.">
          <Row label="Graphics renderer" desc="Default is the most compatible choice."><select className={selectClass} aria-label="Graphics renderer" value={renderer} disabled={locked} onChange={e => patch(rendererPatch(e.target.value))}><option value="default">Roblox default</option><option value={RENDERER_FLAGS[0]}>Direct3D 11</option><option value={RENDERER_FLAGS[1]}>Vulkan</option><option value={RENDERER_FLAGS[2]}>OpenGL</option></select></Row>
          <Row label="Texture quality" desc="Use Roblox default or override the texture level."><select className={selectClass} aria-label="Texture quality" disabled={locked} value={flagBool(flags,"DFFlagTextureQualityOverrideEnabled") ? String(flags.DFIntTextureQualityOverride ?? 3) : "default"} onChange={e => patch({ DFFlagTextureQualityOverrideEnabled:e.target.value==="default"?null:true, DFIntTextureQualityOverride:e.target.value==="default"?null:Number(e.target.value) })}><option value="default">Roblox default</option>{["Lowest","Low","Medium","Highest"].map((v,i)=><option key={i} value={i}>{v}</option>)}</select></Row>
          <Row label="Anti-aliasing" desc="Override MSAA samples. Renderer support varies."><select className={selectClass} aria-label="Anti-aliasing" disabled={locked} value={String(flags.FIntDebugForceMSAASamples ?? "default")} onChange={e=>patch({FIntDebugForceMSAASamples:e.target.value==="default"?null:Number(e.target.value)})}><option value="default">Roblox default</option>{[1,2,4].map(v=><option key={v} value={v}>{v}× MSAA</option>)}</select></Row>
          <Row label="Gray sky" desc="Use the simple gray sky override."><Toggle enabled={flagBool(flags,"FFlagDebugSkyGray")} onChange={v=>patch({FFlagDebugSkyGray:v?true:null})} disabled={locked} ariaLabel="Gray sky" /></Row>
          <Row label="Pause voxel lighting" desc="Reduces lighting updates; appearance may change."><Toggle enabled={flagBool(flags,"DFFlagDebugPauseVoxelizer")} onChange={v=>patch({DFFlagDebugPauseVoxelizer:v?true:null})} disabled={locked} ariaLabel="Pause voxel lighting" /></Row>
          <Row label="Disable DPI scaling" desc="Keep rendering at the display's unscaled resolution."><Toggle enabled={flagBool(flags,"DFFlagDisableDPIScale")} onChange={v=>patch({DFFlagDisableDPIScale:v?true:null})} disabled={locked} ariaLabel="Disable DPI scaling" /></Row>
        </FlagSection>
        <Panel eyebrow="Starting points" desc="A preset replaces this draft. Review it before saving." watermark={{icon:"optimize",at:"right",size:100,opacity:.035}}><div className="flex flex-wrap items-center justify-between gap-3"><select aria-label="FastFlag preset" value={preset} onChange={e=>setPreset(e.target.value as typeof preset)} className={selectClass} disabled={busy}><option value="default">Roblox defaults</option><option value="balanced">Compatible rendering</option><option value="performance">Lowest detail</option></select><Button variant="secondary" size="sm" disabled={busy} onClick={()=>{const next=flagPreset(preset);setFlags(next);setEnabled(Object.keys(next).length>0);}}>Stage preset</Button></div></Panel>
      </> : <Panel eyebrow="Advanced editor" title="Your override list" desc="Add supported flags individually or edit JSON. Supported keys are validated before they are applied." watermark={{ icon: "settings",at:"top-right",size:145,rotate:-12,opacity:.035 }}>
        <div className="mb-3 flex flex-wrap items-center gap-2"><div className="relative min-w-[150px] flex-1"><Icon name="search" size={13} className="absolute left-2.5 top-2.5 text-text-muted" /><input aria-label="Search FastFlags" placeholder="Find a flag..." value={search} onChange={e=>setSearch(e.target.value)} className="w-full rounded-lg border border-border-default bg-bg-base py-2 pl-8 pr-3 text-xs outline-none focus:border-border-focus" /></div><Button variant="secondary" size="sm" disabled={busy||!!rawError && Object.keys(flags).length>0} onClick={()=>setAdding(true)}>Add flag</Button><Button variant="ghost" size="sm" onClick={()=>setJsonView(v=>!v)}>{jsonView?"List view":"Edit JSON"}</Button></div>
        {jsonView ? <textarea aria-label="FastFlag JSON" value={raw} onChange={e=>{setRaw(e.target.value);setNotice(null);}} spellCheck={false} disabled={busy} className="min-h-[240px] w-full resize-y rounded-lg border border-border-default bg-bg-base p-3 font-mono text-[11px] leading-relaxed outline-none focus:border-border-focus" /> : <div className="space-y-1">{rows.length ? rows.map(([name,value])=><div key={name} className="flex flex-wrap items-center gap-2 rounded-lg border border-border-subtle bg-bg-base p-2"><code className="min-w-0 flex-1 break-all text-[10.5px] text-text-secondary">{name}</code><input aria-label={`Value for ${name}`} value={String(value)} onChange={e=>patch({[name]:e.target.value})} disabled={busy} className="w-24 rounded-md border border-border-default bg-bg-elevated px-2 py-1.5 font-mono text-[11px] outline-none focus:border-border-focus" /><button aria-label={`Remove ${name}`} disabled={busy} onClick={()=>patch({[name]:null})} className="rounded-md p-1.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"><Icon name="trash" size={14} /></button></div>) : <p className="py-8 text-center text-xs text-text-muted">{search?"No matching overrides.":"No overrides in this draft. Add a supported flag or choose a preset."}</p>}</div>}
        <details className="mt-4 border-t border-border-subtle pt-3 text-[11px] text-text-muted"><summary className="cursor-pointer">View {FLAG_KEYS.length} supported flag names</summary><div className="mt-3 space-y-1 break-all font-mono text-[10px]">{FLAG_KEYS.map(key=><p key={key}>{key}</p>)}</div></details>
      </Panel>}
      {changed && <div className="sticky bottom-3 z-20 flex items-center justify-between gap-3 rounded-[var(--radius-card)] surface-elevated px-4 py-3"><p className="text-[11px] text-text-secondary">{validation?"Fix the draft before saving.":"Unsaved FastFlag changes"}</p><div className="flex gap-2"><Button variant="secondary" size="sm" onClick={reload} disabled={busy}>Discard</Button><Button size="sm" loading={busy} disabled={!!validation||externalChange} onClick={()=>void save()}>Save & apply</Button></div></div>}
    </div>}
    <Dialog open={closing} title="Close Roblox to apply FastFlags" description="This ends the current game. Flags take effect the next time you launch Roblox." onClose={()=>{if(!busy)setClosing(false);}}><div className="space-y-4 p-4">{error&&<ErrorBanner tone="error">{error}</ErrorBanner>}<div className="flex justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={()=>setClosing(false)}>Cancel</Button><Button loading={busy} onClick={()=>void save(true)}>Close Roblox & apply</Button></div></div></Dialog>
    <Dialog open={reset} title="Reset this flag draft?" description="Removes all editor overrides and turns off management. Save & apply to update Roblox. Other settings and accounts stay intact." onClose={()=>setReset(false)}><div className="flex justify-end gap-2 p-4"><Button variant="secondary" onClick={()=>setReset(false)}>Cancel</Button><Button onClick={()=>{setFlags({});setEnabled(false);setReset(false);}}>Reset draft</Button></div></Dialog>
    <Dialog open={adding} title="Add a supported FastFlag" onClose={()=>setAdding(false)}><div className="space-y-4 p-4"><label className="block text-xs text-text-secondary">Flag name<select aria-label="Flag name" className={`${selectClass} mt-2 !max-w-none w-full`} value={key} onChange={e=>{setKey(e.target.value);setValue(booleanFlag(e.target.value)?"False":"0");}}>{FLAG_KEYS.map(k=><option key={k}>{k}</option>)}</select></label><label className="block text-xs text-text-secondary">Value<input aria-label="Flag value" value={value} onChange={e=>setValue(e.target.value)} className="mt-2 w-full rounded-lg border border-border-default bg-bg-base p-2 font-mono text-xs" /></label><p className="text-[11px] text-text-muted">{booleanFlag(key)?"Enter True or False.":"Enter an integer. Advanced values may change visuals or renderer behaviour."}</p><div className="flex justify-end gap-2"><Button variant="secondary" onClick={()=>setAdding(false)}>Cancel</Button><Button disabled={!!validateCustomFflags(true,JSON.stringify({...flags,[key]:value}))} onClick={()=>{patch({[key]:value});setEnabled(true);setAdding(false);}}>Add to draft</Button></div></div></Dialog>
  </div>;
}

function FlagSlider({label,desc,enabled,value,min,max,step=1,unit="",disabled,onToggle,onChange}:{label:string;desc:string;enabled:boolean;value:number;min:number;max:number;step?:number;unit?:string;disabled:boolean;onToggle:(v:boolean)=>void;onChange:(v:number)=>void}) {
  return <div><Row label={label} desc={desc}><Toggle ariaLabel={label} enabled={enabled} onChange={onToggle} disabled={disabled} /></Row>{enabled&&<div className="flex items-center gap-4 bg-bg-base/40 px-3.5 py-3"><span className="text-[10px] text-text-muted">{min}</span><Slider ariaLabel={`${label} value`} value={value} min={min} max={max} step={step} onChange={onChange} disabled={disabled} /><span className="min-w-16 text-right font-mono text-[11px] text-text-secondary">{value} {unit}</span></div>}</div>;
}
