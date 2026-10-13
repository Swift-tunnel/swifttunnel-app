import { useEffect, useState } from "react";
import { Button, Dialog, ErrorBanner, Icon, Panel, Row, Segmented, Select, SliderInput, Spinner } from "../ui";
import { gamesNvidiaProfile, gamesSaveNvidia } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import type { NvidiaDriverProfile } from "../../lib/types";
import { Notice } from "./Notice";

const controls = [
  {id:0x1057eb71,anchor:"nvidia_power",label:"Power management",desc:"Maximum performance may increase power use and heat.",short:null,options:[[0,"Adaptive"],[1,"Prefer maximum performance"],[2,"Driver controlled"],[5,"Normal"]]},
  {id:0x00a879cf,anchor:"nvidia_vsync",label:"Vertical sync",desc:"Off may reduce latency but can introduce screen tearing.",short:["App setting","Off","On"],options:[[0x60925292,"Use application's setting"],[0x08416747,"Off"],[0x47814940,"On"]]},
  {id:0x007ba09e,anchor:"nvidia_prerender",label:"Maximum pre-rendered frames",desc:"Driver queue limit for supported Direct3D modes. Not NVIDIA Reflex.",short:["App","1","2","3","4"],options:[[0,"Application controlled"],[1,"1 frame"],[2,"2 frames"],[3,"3 frames"],[4,"4 frames"]]},
] as const;
const FPS=0x10835002;
export function NvidiaPanel() {
  const [profile,setProfile]=useState<NvidiaDriverProfile|null>(null);
  const [draft,setDraft]=useState<Record<number,string>>({});
  const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState<string|null>(null);
  const [notice,setNotice]=useState<string|null>(null);
  const [review,setReview]=useState(false);
  function adopt(result:NvidiaDriverProfile){setProfile(result);setDraft(Object.fromEntries(result.settings.map(s=>[s.id,s.override_value===null?"default":String(s.override_value)])));}
  useEffect(()=>{let active=true;void gamesNvidiaProfile().then(result=>{if(active)adopt(result);}).catch(e=>{if(active)setError(formatErrorMessage(e));}).finally(()=>{if(active)setLoading(false);});return()=>{active=false;};},[]);
  const changed=profile?.settings.filter(s=>draft[s.id]!== (s.override_value===null?"default":String(s.override_value)))??[];
  const locked=busy||!profile?.writable;
  const fps=draft[FPS];
  const invalidFps=fps!==undefined&&fps!=="default"&&(!/^\d+$/.test(fps)||Number(fps)>1023);
  async function refresh(){setBusy(true);setError(null);setNotice(null);try{adopt(await gamesNvidiaProfile());}catch(e){setError(formatErrorMessage(e));}finally{setBusy(false);}}
  async function save(){if(!profile||invalidFps)return;setBusy(true);setError(null);try{const result=await gamesSaveNvidia(changed.map(s=>({id:s.id,value:draft[s.id]==="default"?null:Number(draft[s.id])})),profile.settings);adopt(result);setNotice("Saved only the changed settings in Roblox Player's NVIDIA profile. Launch Roblox again for them to take effect.");setReview(false);}catch(e){setError(formatErrorMessage(e));}finally{setBusy(false);}}
  function current(id:number){const setting=profile?.settings.find(s=>s.id===id);if(!setting||setting.current===null)return"Driver default";const choice=controls.find(c=>c.id===id)?.options.find(([v])=>v===setting.current);return choice?.[1]??String(setting.current);}
  return <div className="flex flex-col gap-4"><Panel anchorId="nvidia_profile" eyebrow="NVIDIA driver" title="Roblox Player profile" desc="These are driver settings, separate from Roblox FastFlags. Your global GPU profile and other games stay untouched." watermark={{icon:"gpu",at:"right",size:150,rotate:-12,fade:true,opacity:.05}} actions={<Button variant="secondary" size="sm" disabled={busy||loading} onClick={()=>void refresh()} leadingIcon={<Icon name="refresh" size={13}/>}>Refresh</Button>}>
    {loading?<p className="flex items-center gap-2.5 text-[12px] text-text-muted"><Spinner size={12}/>Reading the installed NVIDIA driver...</p>:!profile?.available?<p className="rounded-[10px] bg-bg-base px-3.5 py-3 text-[12px] leading-relaxed text-text-muted">{profile?.reason??error??"NVIDIA driver controls are unavailable."}</p>:<p className="font-mono text-[10.5px] text-text-muted">RobloxPlayerBeta.exe · {profile.writable?"Changes apply after confirmation":"Read-only shared profile"}</p>}
    {profile?.available&&profile.reason&&<p className="mt-2.5 text-[11.5px] leading-snug text-status-warning">{profile.reason}</p>}
  </Panel>
  {error&&profile?.available&&<ErrorBanner tone="error">{error}</ErrorBanner>}{notice&&<Notice>{notice}</Notice>}
  {profile?.available&&<><Panel eyebrow="Rendering & latency" flush><div className="divide-y divide-border-subtle border-t border-border-subtle">{controls.map(control=>{const selected=draft[control.id]??"default";const custom=selected!=="default"&&!control.options.some(([v])=>String(v)===selected);return<Row key={control.id} anchorId={control.anchor} label={control.label} desc={`${control.desc} Current: ${current(control.id)}.`}>{control.short&&!custom?<Segmented<string> ariaLabel={control.label} value={selected} disabled={locked} options={[{value:"default",label:"Default"},...control.options.map(([v],i)=>({value:String(v),label:control.short[i]}))]} onChange={next=>setDraft(prev=>({...prev,[control.id]:next}))}/>:<Select aria-label={control.label} value={selected} disabled={locked} onChange={e=>setDraft(prev=>({...prev,[control.id]:e.target.value}))}><option value="default">Driver default</option>{custom&&<option value={selected}>Existing value ({selected})</option>}{control.options.map(([v,label])=><option value={v} key={v}>{label}</option>)}</Select>}</Row>;})}
    <Row anchorId="nvidia_fps_limit" label="Driver frame-rate limit" desc="0 disables the limiter. This can cap FPS below Roblox's own setting."><div className="flex items-center gap-3">{fps!=="default"&&<SliderInput ariaLabel="Driver FPS limit" value={Number(fps)||0} min={0} max={1023} step={5} unit="FPS" width={120} disabled={locked} onChange={next=>setDraft(prev=>({...prev,[FPS]:String(next)}))}/>}<Segmented<string> ariaLabel="Driver frame-rate limit mode" disabled={locked} value={fps==="default"?"default":"custom"} options={[{value:"default",label:"Default"},{value:"custom",label:"Limit"}]} onChange={mode=>setDraft(prev=>({...prev,[FPS]:mode==="default"?"default":"0"}))}/></div></Row></div></Panel>
    {invalidFps&&<ErrorBanner tone="warning">Enter a whole FPS limit from 0 to 1023.</ErrorBanner>}
    <div className="flex flex-wrap items-center justify-between gap-3"><Button variant="ghost" size="sm" className="-ml-3" disabled={locked} onClick={()=>setDraft(Object.fromEntries(profile.settings.map(s=>[s.id,"default"])))}>Stage driver defaults</Button><div className="flex gap-2"><Button variant="secondary" size="sm" disabled={busy||!changed.length} onClick={()=>adopt(profile)}>Discard</Button><Button size="sm" disabled={locked||!changed.length||invalidFps} onClick={()=>setReview(true)}>Review changes</Button></div></div></>}
  <Dialog open={review} title="Apply Roblox's NVIDIA profile?" description="Close Roblox first. This changes only the listed settings in Roblox Player's profile, with no global driver reset." onClose={()=>{if(!busy)setReview(false);}}><div className="flex flex-col gap-4"><ul className="divide-y divide-border-subtle rounded-[10px] bg-bg-base">{changed.map(s=><li key={s.id} className="flex items-center justify-between gap-4 px-3.5 py-2.5 text-[12px]"><span className="text-text-secondary">{controls.find(c=>c.id===s.id)?.label??"Frame-rate limit"}</span><span className="text-right font-medium text-text-primary">{draft[s.id]==="default"?"Driver default":controls.find(c=>c.id===s.id)?.options.find(([v])=>String(v)===draft[s.id])?.[1]??draft[s.id]}</span></li>)}</ul>{error&&<ErrorBanner tone="error">{error}</ErrorBanner>}<div className="flex justify-end gap-2"><Button variant="secondary" size="sm" disabled={busy} onClick={()=>setReview(false)}>Cancel</Button><Button size="sm" loading={busy} onClick={()=>void save()}>Apply driver changes</Button></div></div></Dialog>
  </div>;
}
