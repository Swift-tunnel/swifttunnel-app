import { useEffect, useRef, useState } from "react";
import { Button, Dialog, ErrorBanner, Icon } from "../ui";
import { Flag } from "../ui/Flag";
import { gamesDatacenters, gamesSearchServers, systemOpenUrl } from "../../lib/commands";
import { defaultGamePreferences } from "../../lib/gameLaunchFlow";
import { formatErrorMessage } from "../../lib/errors";
import type { RobloxDatacenter, RobloxDirectoryServer, RobloxGameEntry, RobloxServerPage } from "../../lib/types";

export function GameServerDialog({ entry, onClose, onJoin }: { entry: RobloxGameEntry | null; onClose: () => void; onJoin: (entry: RobloxGameEntry, server: RobloxDirectoryServer, center: RobloxDatacenter) => void }) {
  const [centers, setCenters] = useState<RobloxDatacenter[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [page, setPage] = useState<RobloxServerPage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
  const rows = page?.servers ?? [];
  return <Dialog open={!!entry} onClose={onClose} maxWidth={860} title={`Find a server · ${entry?.name ?? "Roblox"}`} description="Choose a Roblox datacenter. A listed server can become full or close before you join.">
    <div className="grid min-h-[300px] grid-cols-[190px_minmax(0,1fr)] max-[700px]:grid-cols-1">
      <div className="max-h-[55vh] overflow-y-auto border-r border-border-subtle p-2 max-[700px]:max-h-[150px]">
        {centers.map(c => <button key={c.id} disabled={busy} onClick={() => void search(c.id)}
          className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-xs transition-colors ${selected === c.id ? "bg-bg-hover text-text-primary" : "text-text-secondary hover:bg-bg-hover"}`}>
          <Flag code={c.country} size={18} /><span className="min-w-0 truncate">{c.city}</span>{selected === c.id && <Icon name="check" size={13} className="ml-auto shrink-0" />}
        </button>)}
      </div>
      <div className="max-h-[55vh] overflow-y-auto p-4">
        {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
        {page?.warning && <ErrorBanner tone="warning">{page.warning}</ErrorBanner>}
        {center && <div className="mb-4 flex items-center justify-between gap-3"><div><p className="text-sm font-semibold text-text-primary">{center.city}</p><p className="mt-1 text-[11px] text-text-muted">{center.relay_region ? `${center.relay_region} relay region` : "No matching SwiftTunnel relay region"}</p></div><Button size="sm" variant="ghost" disabled={busy} onClick={() => void search(center.id)}>Refresh</Button></div>}
        {busy && <div role="status" className="flex items-center gap-2 py-8 text-xs text-text-muted"><span className="h-3 w-3 animate-spin rounded-full border border-current border-t-transparent" />Checking server information...</div>}
        {!busy && !page && !error && <div className="grid min-h-[220px] place-content-center gap-3 text-center text-text-muted"><Icon name="globe" size={32} className="mx-auto" /><p className="text-sm">Choose a datacenter to see its servers.</p>{center && <Button size="sm" variant="secondary" onClick={() => void search(center.id)}>Search {center.city}</Button>}</div>}
        {!busy && page && !rows.length && <p className="py-10 text-center text-xs text-text-muted">No listed server was found here. Refresh or choose another datacenter.</p>}
        <div className="space-y-2">{rows.map(server => <div key={server.job_id} className="flex items-center justify-between gap-3 rounded-xl border border-border-subtle bg-bg-base p-3">
          <div className="min-w-0"><p className="text-xs font-medium text-text-primary">Server {server.job_id.slice(0,8)}</p><p className="mt-1 text-[11px] text-text-muted">{server.playing != null && server.capacity != null ? `${server.playing}/${server.capacity} players · ` : ""}{server.availability === "available" ? "Listed as available" : server.availability === "full" ? "Full" : server.availability === "unavailable" ? "No longer listed" : "Availability unverified"}</p></div>
          <Button size="sm" variant="secondary" disabled={busy || server.availability === "full" || server.availability === "unavailable"} onClick={() => { if (entry && center) onJoin(entry, server, center); }}>Join</Button>
        </div>)}</div>
        {page?.next_cursor != null && rows.length < 200 && <Button size="sm" variant="ghost" className="mt-3" disabled={busy} onClick={() => { if (selected) void search(selected, true); }}>Load more</Button>}
      </div>
    </div>
    <footer className="flex items-center justify-between gap-3 border-t border-border-subtle px-5 py-3 text-[11px] text-text-muted"><span>Server locations by <button className="text-text-secondary underline decoration-border-subtle underline-offset-2" onClick={() => void systemOpenUrl("https://www.rovalra.com")}>RoValra</button>. Availability by Roblox.</span><Button size="sm" variant="ghost" onClick={onClose}>Done</Button></footer>
  </Dialog>;
}
