import { openSystemLink as systemOpenUrl } from "../../lib/openSystemLink";
import { useEffect, useRef, useState } from "react";
import { Button, Dialog, ErrorBanner, Icon, Segmented, SliderInput, Spinner } from "../ui";
import { Flag } from "../ui/Flag";
import { gamesDatacenters, gamesSearchServers } from "../../lib/commands";
import { defaultGamePreferences } from "../../lib/gameLaunchFlow";
import { formatErrorMessage } from "../../lib/errors";
import type { RobloxDatacenter, RobloxDirectoryServer, RobloxGameEntry, RobloxServerPage } from "../../lib/types";

export function GameServerDialog({ entry, onClose, onJoin }: { entry: RobloxGameEntry | null; onClose: () => void; onJoin: (entry: RobloxGameEntry, server: RobloxDirectoryServer, center: RobloxDatacenter) => void }) {
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [page, setPage] = useState<RobloxServerPage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [minSlots,setMinSlots]=useState(1);
  const [population,setPopulation]=useState(false);
  const generation = useRef(0);
  useEffect(() => {
    const current = ++generation.current;
    setPage(null); setError(null); setSelected(entry ? defaultGamePreferences(entry).datacenter_id : null);
    if (!entry) return;
    setBusy(true);
    void gamesDatacenters().then(rows => { if (current === generation.current) setCenters(rows); })
      .catch(error => { if (current === generation.current) setError(formatErrorMessage(error)); })
      .finally(() => { if (current === generation.current) setBusy(false); });
    return () => { ++generation.current; };
  }, [entry]);
  async function search(id: number, more = false) {
    if (!entry) return;
    const current = ++generation.current; setBusy(true); setError(null); setSelected(id);
    if (!more) setPage(null);
    try {
      const next = await gamesSearchServers(entry.place_id, id, more ? page?.next_cursor ?? null : null);
      if (current !== generation.current) return;
      setPage(prev => ({ ...next, servers: more && prev ? [...prev.servers, ...next.servers.filter(row => !prev.servers.some(old => old.job_id === row.job_id))].slice(0, 200) : next.servers }));
    } catch (error) { if (current === generation.current) setError(formatErrorMessage(error)); }
    finally { if (current === generation.current) setBusy(false); }
  }
  const center = centers.find(c => c.id === selected);
  const totalRows=page?.servers??[];
  const rows = totalRows.filter(s=>s.capacity==null||s.playing==null?minSlots===1:s.capacity-s.playing>=minSlots).sort((a,b)=>population?(a.playing??Infinity)-(b.playing??Infinity):0);
  return <Dialog flush open={!!entry} onClose={onClose} maxWidth={820} title={`Find a server · ${entry?.name ?? "Roblox"}`} description="Pick a location, then a server.">
    <div className="grid h-[min(360px,calc(100vh-13rem))] grid-cols-[200px_minmax(0,1fr)] max-[700px]:h-auto max-[700px]:grid-cols-1">
      <div className="overflow-y-auto border-r border-border-subtle p-2.5 max-[700px]:max-h-[150px] max-[700px]:border-b max-[700px]:border-r-0">
        <p className="eyebrow px-2.5 pb-2 pt-1.5">Datacenter</p>
        {centers.map(c => <button key={c.id} type="button" disabled={busy} aria-current={selected === c.id ? "true" : undefined} onClick={() => void search(c.id)}
          className={`flex w-full items-center gap-2.5 rounded-[7px] px-2.5 py-[7px] text-left text-[12px] transition-colors disabled:cursor-not-allowed ${selected === c.id ? "bg-bg-active font-medium text-text-primary" : "text-text-secondary hover:bg-bg-hover"}`}>
          <Flag code={c.country} size={16} /><span className="min-w-0 truncate">{c.city}</span>{selected === c.id && <Icon name="check" size={13} strokeWidth={2.2} className="ml-auto shrink-0" />}
        </button>)}
      </div>
      <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-4">
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2"><div className="flex items-center gap-2.5 text-[11px] text-text-muted">Free slots<SliderInput ariaLabel="Server minimum free slots" value={minSlots} min={1} max={20} width={190} onChange={setMinSlots} /></div><Segmented ariaLabel="Sort public servers" value={population?"few":"listed"} options={[{ value: "listed", label: "As listed" }, { value: "few", label: "Fewer players" }]} onChange={order=>setPopulation(order==="few")} /></div>
        {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
        {page?.warning && <ErrorBanner tone="warning">{page.warning}</ErrorBanner>}
        {center && <div className="flex items-center justify-between gap-3"><div className="min-w-0"><p className="text-[13.5px] font-semibold leading-tight text-text-primary">{center.city}</p><p className="mt-1 text-[11px] text-text-muted">{center.relay_region ? `${center.relay_region} relay region` : "No SwiftTunnel relay for this location"}</p></div><Button size="sm" variant="secondary" disabled={busy} leadingIcon={<Icon name="refresh" size={13} />} onClick={() => void search(center.id)}>Refresh</Button></div>}
        {busy && <div role="status" className={`flex items-center gap-2.5 text-[12px] text-text-muted ${rows.length ? "py-1" : "flex-1 justify-center py-8"}`}><Spinner size={13} />Checking server information...</div>}
        {!busy && !page && !error && <div className="flex flex-1 flex-col items-center justify-center gap-3 py-6 text-center"><div className="icon-orb flex h-10 w-10 items-center justify-center"><Icon name="globe" size={18} strokeWidth={1.8} className="text-text-muted" /></div><p className="text-[12.5px] font-medium text-text-primary">Pick a location to see its servers.</p>{center && <Button size="sm" variant="secondary" onClick={() => void search(center.id)}>Search {center.city}</Button>}</div>}
        {!busy && page && !rows.length && <p className="flex flex-1 items-center justify-center py-8 text-center text-[12px] text-text-muted">No servers found here. Refresh or try another location.</p>}
        {!!rows.length && <div className="divide-y divide-border-subtle rounded-[10px] bg-bg-base">{rows.map(server => <div key={server.job_id} className="flex items-center justify-between gap-3 px-3.5 py-2.5">
          <div className="min-w-0"><p className="font-mono text-[12px] font-medium text-text-primary">Server {server.job_id.slice(0,8)}</p><p className="mt-1 text-[11px] text-text-muted">{server.playing != null && server.capacity != null ? `${server.playing}/${server.capacity} players · ` : ""}{server.availability === "available" ? "Listed as available" : server.availability === "full" ? "Full" : server.availability === "unavailable" ? "No longer listed" : "Availability unverified"}</p></div>
          <Button size="sm" variant="secondary" disabled={busy || server.availability === "full" || server.availability === "unavailable"} onClick={() => { if (entry && center) onJoin(entry, server, center); }}>Join</Button>
        </div>)}</div>}
        {page?.next_cursor != null && totalRows.length < 200 && <Button size="sm" variant="ghost" className="self-start" disabled={busy} onClick={() => { if (selected) void search(selected, true); }}>Load more</Button>}
      </div>
    </div>
    <footer className="flex items-center justify-between gap-3 border-t border-border-subtle px-5 py-3 text-[11px] text-text-muted"><span>Server locations by <button type="button" className="text-text-secondary underline decoration-border-strong underline-offset-2 hover:text-text-primary" onClick={() => void systemOpenUrl("https://www.rovalra.com")}>RoValra</button>. Availability by Roblox.</span><Button size="sm" variant="secondary" onClick={onClose}>Done</Button></footer>
  </Dialog>;
}
