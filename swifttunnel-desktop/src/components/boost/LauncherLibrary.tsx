import { useEffect, useState } from "react";
import { Button, Dialog, ErrorBanner, Icon, Toggle, Watermark } from "../ui";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import { boostCloseRoblox, boostGetMetrics, gamesAddFavourite, gamesForget, gamesLaunch, gamesLaunchPlan, gamesRefreshMetadata, gamesSetFavourite, gamesSetNotifications } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { gameSessionDescription, gameShareUrl, parsePlaceInput } from "../../lib/robloxGames";
import { defaultGamePreferences, executeGameLaunch } from "../../lib/gameLaunchFlow";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import type { GameLaunchPlan, RobloxGameEntry } from "../../lib/types";
import { GamePreferencesDialog } from "./GamePreferencesDialog";
import { GameServerDialog } from "./GameServerDialog";

function Artwork({ entry, large = false }: { entry: RobloxGameEntry; large?: boolean }) {
  const [failed, setFailed] = useState(false);
  return <div className={`relative grid shrink-0 place-items-center overflow-hidden rounded-xl ${large ? "h-20 w-20" : "h-[72px] w-[72px]"}`} style={{ background: "linear-gradient(145deg, var(--color-accent-primary-soft-8), var(--color-bg-hover))" }}>
    {entry.icon_url && !failed ? <img src={entry.icon_url} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" className="h-full w-full object-cover" onError={() => setFailed(true)} />
      : <Icon name="roblox" size={large ? 34 : 28} className="text-text-secondary" />}
  </div>;
}
function Star({ filled }: { filled: boolean }) {
  return <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round"><path d="m12 3 2.8 5.7 6.3.9-4.55 4.43 1.07 6.26L12 17.34l-5.62 2.95 1.07-6.26L2.9 9.6l6.3-.9z" /></svg>;
}
interface Review { entry: RobloxGameEntry; plan: GameLaunchPlan; running: boolean; blocked: boolean; }

export function GameLibraryPanel() {
  const { library, error: loadError, loading, refresh } = useGameLibraryStore();
  const route = useVpnStore(s => s.gameRoute);
  const tunnelState = useVpnStore(s => s.state);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "favourites">("all");
  const [input, setInput] = useState("");
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [profile, setProfile] = useState<RobloxGameEntry | null>(null);
  const [servers, setServers] = useState<RobloxGameEntry | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const [remove, setRemove] = useState<RobloxGameEntry | null>(null);
  const [failedEntry, setFailedEntry] = useState<RobloxGameEntry | null>(null);
  useEffect(() => { void refresh().then(() => { void gamesRefreshMetadata().catch(() => {}); }); }, [refresh]);

  async function run(action: () => Promise<unknown>, after?: string) {
    setBusy(true); setError(null); setNotice(null);
    try { await action(); await refresh(); if (after) setNotice(after); }
    catch (error) { setError(formatErrorMessage(error)); }
    finally { setBusy(false); setProgress(null); }
  }
  async function addFavourite() {
    const place = parsePlaceInput(input);
    if (!place) { setError("Enter a Roblox game link or a numeric place ID."); return; }
    await run(async () => { await gamesAddFavourite(place); setInput(""); setAdding(false); });
  }
  async function launch(entry: RobloxGameEntry, plan: GameLaunchPlan, close: boolean) {
    setReview(null);
    await run(async () => {
      if (close) {
        setProgress("Closing the current Roblox client...");
        await boostCloseRoblox();
        if ((await boostGetMetrics()).roblox_running) throw new Error("Roblox is still closing. Wait a moment, then try Play again.");
      }
      await executeGameLaunch(plan, {
        connect: async requested => {
          const vpn = useVpnStore.getState();
          const existing = vpn.state === "connected";
          const family = findRegionForVpnRegion(useServerStore.getState().regions, vpn.region)?.id;
          if (existing && (!requested || family === requested)) return { owned: false, token: null };
          setProgress("Preparing your SwiftTunnel connection...");
          if (existing) await vpn.disconnect();
          const settings = useSettingsStore.getState().settings;
          await useVpnStore.getState().connect(requested ?? settings.selected_region, settings.selected_game_presets, requested !== null);
          const connected = useVpnStore.getState();
          if (connected.state !== "connected") throw new Error(connected.error ?? "Finish connecting in Connect, then try Play again.");
          if (requested && findRegionForVpnRegion(useServerStore.getState().regions, connected.region)?.id !== requested) throw new Error("The connection did not reach the requested relay region. Check Connect before joining.");
          return { owned: !existing, token: connected.connectedAt };
        },
        launch: async owned => {
          setProgress("Opening Roblox...");
          await gamesLaunch(entry.place_id, entry.client, plan.job_id, plan.datacenter?.id ?? null, true, owned);
        },
        cleanup: async token => { if (token !== null && useVpnStore.getState().connectedAt === token) await useVpnStore.getState().disconnect(); },
      });
    }, entry.client === "vng" ? "Opened the official VNG game page." : "Join request sent to Roblox. Its server information will appear when the game is detected.");
  }
  async function prepare(entry: RobloxGameEntry, job: string | null = null, center: number | null = null, preferred = true) {
    setFailedEntry(null);
    setBusy(true); setError(null); setNotice(null); setProgress("Checking the game and server...");
    try {
      const [plan, metrics] = await Promise.all([gamesLaunchPlan(entry.place_id, entry.client, job, center, preferred), boostGetMetrics()]);
      const blocked = plan.availability === "full" || plan.availability === "unavailable";
      if (blocked || plan.job_id && plan.availability === "unknown" || metrics.roblox_running) setReview({ entry, plan, running: metrics.roblox_running, blocked });
      else await launch(entry, plan, false);
    } catch (error) { setError(formatErrorMessage(error)); setFailedEntry(entry); }
    finally { setBusy(false); setProgress(null); }
  }
  const entries = library?.entries ?? [];
  const current = library?.current;
  const active = entries.find(e => e.place_id === current?.place_id && e.client === current.client);
  const shown = entries.filter(e => (filter !== "favourites" || e.favourite) && `${e.name} ${e.place_id}`.toLowerCase().includes(query.toLowerCase()));
  const locked = busy || !!library?.launch_pending;

  return <div className="space-y-5">
    {(error || loadError || library?.warning) && <ErrorBanner tone="error">{error || loadError || library?.warning}</ErrorBanner>}
    {failedEntry && <Button size="sm" variant="secondary" disabled={busy} onClick={() => void prepare(failedEntry, null, null, false)}>Play normally without a preferred server</Button>}
    {(notice || progress) && <p role="status" className="rounded-xl border border-border-subtle bg-bg-hover px-4 py-3 text-xs text-text-secondary">{progress ?? notice}</p>}
    {current && <section className="instrument relative isolate flex items-center gap-4 px-5 py-4"><Watermark icon="roblox" at="right" size={150} rotate={-14} fade opacity={.045} />
      {active && <Artwork entry={active} large />}<div className="min-w-0 flex-1"><p className="text-[10px] font-semibold uppercase tracking-[.14em] text-text-muted">Game session</p><h2 className="mt-1 truncate text-lg font-semibold text-text-primary">{active?.name ?? `Place ${current.place_id}`}</h2><p className="mt-1 text-xs text-text-secondary">{gameSessionDescription(current, tunnelState === "connected" ? route : null)}</p></div>
      <span className="hidden rounded-full border border-border-subtle px-3 py-1.5 text-[11px] text-text-secondary min-[950px]:block">{tunnelState === "connected" ? "Tunnel active" : "Current connection"}</span>
    </section>}
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex gap-1 rounded-xl border border-border-subtle p-1">{(["all", "favourites"] as const).map(value => <button key={value} className={`rounded-lg px-3 py-1.5 text-xs transition-colors ${filter === value ? "bg-bg-hover font-semibold text-text-primary" : "text-text-muted hover:text-text-primary"}`} onClick={() => setFilter(value)}>{value === "all" ? "Recent & saved" : "Favourites"}</button>)}</div>
      <label className="relative min-w-[170px] flex-1"><Icon name="search" size={14} className="absolute left-3 top-2.5 text-text-muted" /><input aria-label="Find a saved game" placeholder="Find a game" value={query} onChange={e => setQuery(e.target.value)} className="h-9 w-full rounded-xl border border-border-subtle bg-bg-base pl-9 pr-3 text-xs text-text-primary" /></label>
      <Button size="sm" variant="secondary" disabled={locked || !library} onClick={() => { setError(null); setAdding(true); }}>Add game</Button>
      <button aria-label="Refresh games" disabled={locked || loading} className="rounded-lg p-2 text-text-muted hover:bg-bg-hover hover:text-text-primary disabled:opacity-40" onClick={() => void run(() => gamesRefreshMetadata())}><Icon name="refresh" size={15} /></button>
    </div>
    {!library && loading && <div className="grid grid-cols-2 gap-3" aria-label="Loading games">{[1,2,3,4].map(i => <div key={i} className="h-[150px] animate-pulse rounded-2xl border border-border-subtle bg-bg-hover" />)}</div>}
    {library && !entries.length && <div className="grid min-h-[250px] place-content-center gap-3 rounded-2xl border border-dashed border-border-subtle px-6 text-center"><Icon name="games" size={36} className="mx-auto text-text-muted" /><h2 className="text-base font-semibold text-text-primary">Your next game starts here.</h2><p className="max-w-[330px] text-xs leading-relaxed text-text-muted">Join a game with SwiftTunnel open, or add a favourite above. Keep a small library of the games you actually play.</p></div>}
    {library && !!entries.length && !shown.length && <p className="py-12 text-center text-xs text-text-muted">No games match this view.</p>}
    <div className="grid grid-cols-[repeat(auto-fit,minmax(270px,1fr))] gap-3">{shown.map(entry => {
      const preferences = defaultGamePreferences(entry);
      return <article key={`${entry.client}:${entry.place_id}`} className="instrument group relative isolate overflow-hidden transition-colors hover:border-border-default"><Watermark icon="games" at="bottom-right" size={120} rotate={-12} opacity={.025} />
        <div className="flex items-start gap-3.5 p-4"><Artwork entry={entry} /><div className="min-w-0 flex-1"><h3 className="line-clamp-2 text-[14px] font-semibold leading-snug text-text-primary" title={entry.name}>{entry.name}</h3><p className="mt-1.5 text-[11px] text-text-muted">{entry.client === "vng" ? "Roblox VNG" : "Roblox"}{entry.last_played ? ` · ${new Date(entry.last_played * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" })}` : " · Saved"}</p><p className="mt-2 text-[10px] text-text-secondary">{preferences.fps_cap ? `${preferences.fps_cap === 99999 ? "Uncapped" : `${preferences.fps_cap} FPS`} · ` : ""}{preferences.datacenter_id ? "Preferred region" : preferences.use_tunnel ? "Automatic connection" : "Use current connection"}</p></div>
          <button aria-label={`${entry.favourite ? "Remove" : "Add"} ${entry.name} ${entry.favourite ? "from" : "to"} favourites`} aria-pressed={entry.favourite} disabled={locked || !!loadError} className="rounded-lg p-1.5 text-text-secondary hover:bg-bg-hover" onClick={() => void run(() => gamesSetFavourite(entry.place_id, entry.client, !entry.favourite))}><Star filled={entry.favourite} /></button></div>
        <div className="flex items-center gap-1.5 border-t border-border-subtle px-3 py-2.5"><Button size="sm" fullWidth disabled={locked} onClick={() => void prepare(entry)}>Play</Button>
          {entry.job_id && entry.client === "standard" && <Button size="sm" variant="ghost" disabled={locked} onClick={() => void prepare(entry, entry.job_id, null, false)}>Rejoin</Button>}
          <button title="Game settings" aria-label={`Settings for ${entry.name}`} disabled={locked} className="rounded-lg p-2 text-text-muted hover:bg-bg-hover hover:text-text-primary" onClick={() => setProfile(entry)}><Icon name="settings" size={15} /></button>
          <details className="relative"><summary aria-label={`More actions for ${entry.name}`} className="list-none cursor-pointer rounded-lg px-2 py-1.5 text-text-muted hover:bg-bg-hover">···</summary><div className="absolute bottom-9 right-0 z-20 w-40 rounded-xl border border-border-default bg-bg-elevated p-1.5 shadow-xl">
            {entry.client === "standard" && <><button disabled={locked} className="w-full rounded-lg px-3 py-2 text-left text-xs text-text-secondary hover:bg-bg-hover" onClick={() => setServers(entry)}>Find server</button><button disabled={locked} className="w-full rounded-lg px-3 py-2 text-left text-xs text-text-secondary hover:bg-bg-hover" onClick={() => void run(() => navigator.clipboard.writeText(gameShareUrl(entry.place_id, entry.job_id)), "Join link copied.")}>Copy link</button></>}
            <button disabled={locked || !!loadError} className="w-full rounded-lg px-3 py-2 text-left text-xs text-text-muted hover:bg-bg-hover" onClick={() => setRemove(entry)}>Forget game</button></div></details>
        </div>
      </article>;
    })}</div>
    {library && <div className="flex items-center justify-between gap-4 border-t border-border-subtle pt-4"><div><p className="text-xs font-medium text-text-secondary">Join notifications</p><p className="mt-1 text-[11px] text-text-muted">Show the detected server and its verified estimate once per join.</p></div><Toggle enabled={library.notify_joins} disabled={locked || !!loadError} ariaLabel="Server information notification" onChange={enabled => void run(() => gamesSetNotifications(enabled))} /></div>}
    <GamePreferencesDialog entry={profile} onClose={() => setProfile(null)} onSaved={() => void refresh()} />
    <GameServerDialog entry={servers} onClose={() => setServers(null)} onJoin={(entry, server, center) => { setServers(null); void prepare(entry, server.job_id, center.id, false); }} />
    <Dialog open={adding} onClose={() => { if (!busy) setAdding(false); }} title="Add a game" description="Paste its official Roblox game link or place ID. No Roblox sign-in is needed here.">
      <form onSubmit={e => { e.preventDefault(); void addFavourite(); }} className="space-y-4 p-5">{error && <ErrorBanner tone="error">{error}</ErrorBanner>}<input autoFocus aria-label="Roblox game link or place ID" value={input} onChange={e => setInput(e.target.value)} maxLength={2048} placeholder="https://www.roblox.com/games/..." disabled={busy} className="w-full rounded-xl border border-border-subtle bg-bg-base px-3 py-3 text-sm text-text-primary" /><div className="flex justify-end gap-2"><Button type="button" variant="ghost" disabled={busy} onClick={() => setAdding(false)}>Cancel</Button><Button type="submit" loading={busy} disabled={!input.trim()}>Add favourite</Button></div></form>
    </Dialog>
    <Dialog open={!!review} onClose={() => { if (!busy) setReview(null); }} title={review?.blocked ? "That server is unavailable" : review?.running ? "Ready to change games?" : "Join this server?"}
      description={review?.blocked ? "It is full or no longer listed. You can join the game normally instead." : review?.running ? review.plan.needs_close ? "Your current Roblox client will close so its settings and route can be prepared safely." : "This may leave your current game." : "Current availability could not be verified. Roblox may report that it is full or closed."}>
      <div className="p-5"><p className="text-sm font-semibold text-text-primary">{review?.entry.name}</p>{review?.plan.datacenter && <p className="mt-1 text-xs text-text-secondary">{review.plan.datacenter.city}, {review.plan.datacenter.country}</p>}{error && <ErrorBanner tone="error">{error}</ErrorBanner>}<div className="mt-5 flex justify-end gap-2"><Button variant="ghost" disabled={busy} onClick={() => setReview(null)}>Cancel</Button>
        <Button variant={review?.blocked ? "primary" : "secondary"} disabled={busy} onClick={() => { if (review) { const entry = review.entry; setReview(null); void prepare(entry, null, null, false); } }}>Play normally</Button>
        {!review?.blocked && <Button loading={busy} onClick={() => { if (review) void launch(review.entry, review.plan, review.running && review.plan.needs_close); }}>{review?.running && review.plan.needs_close ? "Close Roblox & play" : "Join server"}</Button>}</div></div>
    </Dialog>
    <Dialog open={!!remove} onClose={() => { if (!busy) setRemove(null); }} title="Forget this game?" description="Removes its local history, profile and favourite. Your Roblox account is unchanged."><div className="flex justify-end gap-2 p-5"><Button variant="ghost" disabled={busy} onClick={() => setRemove(null)}>Cancel</Button><Button variant="destructive" loading={busy} onClick={() => { if (remove) void run(async () => { await gamesForget(remove.place_id, remove.client); setRemove(null); }); }}>Forget</Button></div></Dialog>
  </div>;
}
