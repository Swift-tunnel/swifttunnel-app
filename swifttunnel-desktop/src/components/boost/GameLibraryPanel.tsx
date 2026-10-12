import { useEffect, useState } from "react";
import { Button, Dialog, ErrorBanner, Panel, Toggle } from "../ui";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import { useVpnStore } from "../../stores/vpnStore";
import { gamesAddFavourite, gamesForget, gamesJoin, gamesSetFavourite, gamesSetNotifications } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { gameSessionDescription, gameShareUrl, parsePlaceInput } from "../../lib/robloxGames";
import type { RobloxGameEntry } from "../../lib/types";

export function GameLibraryPanel() {
  const { library, error: loadError, loading, refresh } = useGameLibraryStore();
  const route = useVpnStore(s => s.gameRoute);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const [join, setJoin] = useState<{ entry: RobloxGameEntry; rejoin: boolean } | null>(null);
  const [remove, setRemove] = useState<RobloxGameEntry | null>(null);
  useEffect(() => { void refresh(); }, [refresh]);

  async function run(action: () => Promise<unknown>, after?: string) {
    setBusy(true); setError(null); setNotice(null);
    try { await action(); await refresh(); if (after) setNotice(after); }
    catch (error) { setError(formatErrorMessage(error)); }
    finally { setBusy(false); }
  }
  async function addFavourite() {
    const place = parsePlaceInput(input);
    if (!place) { setError("Enter a Roblox game link or a numeric place ID."); return; }
    await run(async () => { await gamesAddFavourite(place); setInput(""); });
  }
  async function launch(entry: RobloxGameEntry, rejoin: boolean) {
    await run(() => gamesJoin(entry.place_id, entry.client, rejoin ? entry.job_id : null),
      entry.client === "vng" ? "Opened the VNG game page." : "Sent the join request to your Roblox launcher.");
    setJoin(null);
  }
  const entries = library?.entries ?? [];
  const shown = all ? entries : entries.slice(0, 6);
  const current = library?.current;

  return <Panel eyebrow="Your games" title="Recent games & favourites"
    desc="Launch with your registered Roblox launcher. Your game list stays on this PC."
    actions={<Button size="sm" variant="ghost" disabled={loading || busy} onClick={() => void refresh()}>Refresh</Button>}>
    {(error || loadError || library?.warning) && <ErrorBanner tone="error">{error || loadError || library?.warning}</ErrorBanner>}
    {notice && <p role="status" className="mb-3 text-xs text-text-secondary">{notice}</p>}
    {current && <div className="mb-3 rounded-lg bg-bg-hover px-3 py-2 text-xs text-text-secondary">
      <p className="font-semibold text-text-primary">{entries.find(e => e.place_id === current.place_id && e.client === current.client)?.name ?? `Place ${current.place_id}`}</p>
      <p className="mt-1">{gameSessionDescription(current, route)}</p>
    </div>}
    <form className="mb-3 flex flex-wrap gap-2" onSubmit={e => { e.preventDefault(); void addFavourite(); }}>
      <input aria-label="Roblox game link or place ID" value={input} onChange={e => setInput(e.target.value)}
        placeholder="Paste a game link or place ID" maxLength={2048} disabled={busy || !library}
        className="min-w-[180px] flex-1 rounded-lg border border-border-subtle bg-bg-base px-3 py-2 text-xs text-text-primary" />
      <Button type="submit" size="sm" variant="secondary" disabled={busy || !library || !input.trim()}>Add favourite</Button>
    </form>
    {!library && loading && <p className="text-xs text-text-muted">Loading your game list...</p>}
    {library && !entries.length && <p className="py-3 text-xs text-text-muted">Join a game with SwiftTunnel open, or add a favourite above.</p>}
    <div className="divide-y divide-border-subtle">
      {shown.map(entry => <div key={`${entry.client}:${entry.place_id}`} className="flex flex-wrap items-center gap-2 py-3">
        <button aria-label={`${entry.favourite ? "Remove" : "Add"} ${entry.name} ${entry.favourite ? "from" : "to"} favourites`}
          aria-pressed={entry.favourite} disabled={busy || !!loadError} className="px-1 text-base text-text-secondary"
          onClick={() => void run(() => gamesSetFavourite(entry.place_id, entry.client, !entry.favourite))}>{entry.favourite ? "★" : "☆"}</button>
        <div className="min-w-[120px] flex-1">
          <p className="truncate text-xs font-semibold text-text-primary" title={entry.name}>{entry.name}</p>
          <p className="mt-1 text-[11px] text-text-muted">{entry.client === "vng" ? "Roblox VNG · " : ""}{entry.last_played ? `Last joined ${new Date(entry.last_played * 1000).toLocaleDateString()}` : "Favourite"}</p>
        </div>
        <Button size="sm" variant="secondary" disabled={busy} onClick={() => {
          if (current) setJoin({ entry, rejoin: false }); else void launch(entry, false);
        }}>Play</Button>
        {entry.job_id && entry.client === "standard" && <Button size="sm" variant="ghost" disabled={busy}
          onClick={() => setJoin({ entry, rejoin: true })}>Rejoin</Button>}
        {entry.client === "standard" && <Button size="sm" variant="ghost" disabled={busy}
          onClick={() => void run(() => navigator.clipboard.writeText(gameShareUrl(entry.place_id, entry.job_id)), "Join link copied. The server may have closed or restricted access.")}>Copy link</Button>}
        <Button size="sm" variant="ghost" disabled={busy || !!loadError} onClick={() => setRemove(entry)} aria-label={`Forget ${entry.name}`}>Forget</Button>
      </div>)}
    </div>
    {entries.length > 6 && <Button size="sm" variant="ghost" onClick={() => setAll(v => !v)}>{all ? "Show fewer" : `Show all ${entries.length}`}</Button>}
    {library && <div className="mt-3 flex items-center justify-between gap-3 border-t border-border-subtle pt-3">
      <div><p className="text-xs text-text-primary">Server information notification</p><p className="mt-1 text-[11px] text-text-muted">One notification per join. Ping appears only when the route is verified.</p></div>
      <Toggle enabled={library.notify_joins} ariaLabel="Server information notification" disabled={busy || !!loadError}
        onChange={enabled => void run(() => gamesSetNotifications(enabled))} />
    </div>}
    <Dialog open={!!join} onClose={() => { if (!busy) setJoin(null); }} title={join?.rejoin ? "Rejoin the last server?" : "Open another game?"}
      description={join?.rejoin ? "The server may be full, closed or private. If Roblox cannot join it, use Play to join the game normally." : "This can leave your current game."}>
      <div className="flex justify-end gap-2 p-4"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setJoin(null)}>Cancel</Button>
        {join?.rejoin && <Button size="sm" variant="secondary" disabled={busy} onClick={() => void launch(join.entry, false)}>Play normally</Button>}
        <Button size="sm" loading={busy} onClick={() => { if (join) void launch(join.entry, join.rejoin); }}>{join?.rejoin ? "Rejoin server" : "Play"}</Button></div>
    </Dialog>
    <Dialog open={!!remove} onClose={() => { if (!busy) setRemove(null); }} title="Forget this game?" description="Removes its local history and favourite. Your Roblox account is unchanged.">
      <div className="flex justify-end gap-2 p-4"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setRemove(null)}>Cancel</Button>
        <Button size="sm" variant="destructive" loading={busy} onClick={() => { if (remove) void run(async () => { await gamesForget(remove.place_id, remove.client); setRemove(null); }); }}>Forget</Button></div>
    </Dialog>
  </Panel>;
}
