import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button, Dialog, EmptyState, ErrorBanner, Icon, Row, Toggle, Watermark, fieldClass } from "../ui";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useServerStore } from "../../stores/serverStore";
import { boostCloseRoblox, boostGetMetrics, gamesAddFavourite, gamesForget, gamesLaunch, gamesLaunchPlan, gamesRefreshMetadata, gamesSetFavourite, gamesSetNotifications, gamesDismissRecovery, gamesCreateShortcut, gamesSuggestServer } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { gameSessionDescription, gameShareUrl, parsePlaceInput } from "../../lib/robloxGames";
import { defaultGamePreferences, executeGameLaunch } from "../../lib/gameLaunchFlow";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import type { GameLaunchPlan, RobloxGameEntry } from "../../lib/types";
import { GamePreferencesDialog } from "./GamePreferencesDialog";
import { GameServerDialog } from "./GameServerDialog";
import { Notice, iconButtonClass } from "./Notice";
import { SessionReportsPanel } from "./SessionReportsPanel";

function Artwork({ entry }: { entry: RobloxGameEntry }) {
  const [failed, setFailed] = useState(false);
  return <div className="grid h-[60px] w-[60px] shrink-0 place-items-center overflow-hidden rounded-[10px] bg-bg-elevated">
    {entry.icon_url && !failed ? <img src={entry.icon_url} alt="" loading="lazy" decoding="async" referrerPolicy="no-referrer" className="h-full w-full object-cover" onError={() => setFailed(true)} />
      : <Icon name="roblox" size={24} className="text-text-muted" />}
  </div>;
}
function Star({ filled }: { filled: boolean }) {
  return <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round"><path d="m12 3 2.8 5.7 6.3.9-4.55 4.43 1.07 6.26L12 17.34l-5.62 2.95 1.07-6.26L2.9 9.6l6.3-.9z" /></svg>;
}
const menuItemClass = "flex w-full items-center rounded-[6px] px-2.5 py-1.5 text-left text-[12px] transition-colors hover:bg-bg-hover disabled:cursor-not-allowed disabled:opacity-40";
/** A card's overflow menu. It closes on a choice, a click elsewhere or Escape. */
function ActionMenu({ label, children }: { label: string; children: ReactNode }) {
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const dismiss = (event: MouseEvent | KeyboardEvent) => {
      const element = menu.current;
      if (!element?.open) return;
      if ("key" in event ? event.key === "Escape" : !element.contains(event.target as Node)) element.open = false;
    };
    document.addEventListener("mousedown", dismiss);
    document.addEventListener("keydown", dismiss);
    return () => { document.removeEventListener("mousedown", dismiss); document.removeEventListener("keydown", dismiss); };
  }, []);
  return <details ref={menu} className="relative">
    <summary aria-label={label} className={`${iconButtonClass} cursor-pointer list-none [&::-webkit-details-marker]:hidden`}>
      <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.7" /><circle cx="12" cy="12" r="1.7" /><circle cx="19" cy="12" r="1.7" /></svg>
    </summary>
    <div className="surface-elevated absolute right-0 top-[34px] z-20 w-40 rounded-[10px] p-1" onClick={() => { if (menu.current) menu.current.open = false; }}>{children}</div>
  </details>;
}
interface Review { entry: RobloxGameEntry; plan: GameLaunchPlan; running: boolean; blocked: boolean; safe: boolean; }

export function GameLibraryPanel() {
  const { library, error: loadError, loading, refresh } = useGameLibraryStore();
  const pendingAction=useGameLibraryStore(s=>s.pendingAction);
  const [reportsOpen,setReportsOpen]=useState(false);
  const [suggestion,setSuggestion]=useState<GameLaunchPlan|null>(null);
  const suggestedJoin=useRef<string|null>(null);
  useEffect(()=>{
    const current=library?.current;
    if(!current?.fresh_join || !current.location || suggestedJoin.current===current.job_id)return;
    let disposed=false;let expire:ReturnType<typeof setTimeout>|undefined;
    const timer=setTimeout(()=>{suggestedJoin.current=current.job_id;void gamesSuggestServer().then(plan=>{if(!disposed&&plan){setSuggestion(plan);expire=setTimeout(()=>setSuggestion(null),20000);}}).catch(()=>{});},5000);
    return()=>{disposed=true;clearTimeout(timer);clearTimeout(expire);setSuggestion(null);};
  },[library?.current?.job_id,library?.current?.location]);
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
  useEffect(()=>{
    if(!pendingAction||!library)return;
    useGameLibraryStore.getState().requestAction(null);
    if(pendingAction==="favourites"){setFilter("favourites");return;}
    if(pendingAction==="copy"){const current=library.current;if(current)void run(()=>navigator.clipboard.writeText(gameShareUrl(current.place_id,current.job_id)),"Join link copied.");return;}
    const last=library.entries.filter(e=>e.client==="standard"&&e.last_played&&e.job_id).sort((a,b)=>(b.last_played??0)-(a.last_played??0))[0];
    const place=pendingAction.startsWith("play:")?parsePlaceInput(pendingAction.slice(5)):null;
    const entry=place?(library.entries.find(e=>e.place_id===place&&e.client==="standard")??{place_id:place,name:`Place ${place}`,client:"standard" as const,job_id:null,last_played:null,favourite:false}):pendingAction==="rejoin"?last:null;
    if(entry)void prepare(entry,pendingAction==="rejoin"?entry.job_id:null,null,pendingAction!=="rejoin");
  },[pendingAction,library]);

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
  async function launch(entry: RobloxGameEntry, plan: GameLaunchPlan, close: boolean, safe=false) {
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
          const presets=settings.selected_game_presets.includes("roblox")?settings.selected_game_presets:[...settings.selected_game_presets,"roblox"];
          await useVpnStore.getState().connect(requested ?? settings.selected_region, presets, requested !== null);
          const connected = useVpnStore.getState();
          if (connected.state !== "connected") throw new Error(connected.error ?? "Finish connecting in Connect, then try Play again.");
          if (requested && findRegionForVpnRegion(useServerStore.getState().regions, connected.region)?.id !== requested) throw new Error("The connection did not reach the requested relay region. Check Connect before joining.");
          return { owned: !existing, token: connected.connectedAt };
        },
        launch: async owned => {
          setProgress("Opening Roblox...");
          await gamesLaunch(entry.place_id, entry.client, plan.job_id, plan.datacenter?.id ?? null, true, owned, safe);
        },
        cleanup: async token => { if (token !== null && useVpnStore.getState().connectedAt === token) await useVpnStore.getState().disconnect(); },
      });
    }, entry.client === "vng" ? "Opened the official VNG game page." : "Join request sent to Roblox. Its server information will appear when the game is detected.");
  }
  async function prepare(entry: RobloxGameEntry, job: string | null = null, center: number | null = null, preferred = true, safe=false) {
    setFailedEntry(null);
    setBusy(true); setError(null); setNotice(null); setProgress("Checking the game and server...");
    try {
      const [plan, metrics] = await Promise.all([gamesLaunchPlan(entry.place_id, entry.client, job, center, preferred), boostGetMetrics()]);
      const blocked = plan.availability === "full" || plan.availability === "unavailable";
      if (blocked || plan.job_id && plan.availability === "unknown" || metrics.roblox_running) setReview({ entry, plan, running: metrics.roblox_running, blocked, safe });
      else await launch(entry, plan, false, safe);
    } catch (error) { setError(formatErrorMessage(error)); setFailedEntry(entry); }
    finally { setBusy(false); setProgress(null); }
  }
  const entries = library?.entries ?? [];
  const current = library?.current;
  const active = entries.find(e => e.place_id === current?.place_id && e.client === current.client);
  const shown = entries.filter(e => (filter !== "favourites" || e.favourite) && `${e.name} ${e.place_id}`.toLowerCase().includes(query.toLowerCase()));
  const locked = busy || !!library?.launch_pending;

  return <div className="flex flex-col gap-4">
    {(error || loadError || library?.warning) && <ErrorBanner tone="error">{error || loadError || library?.warning}</ErrorBanner>}
    {failedEntry && <Button size="sm" variant="secondary" className="self-start" disabled={busy} onClick={() => void prepare(failedEntry, null, null, false)}>Play normally without a preferred server</Button>}
    {(notice || progress) && <Notice busy={!!progress}>{progress ?? notice}</Notice>}
    {library?.status && <Notice>{library.status}</Notice>}
    {current && <section className="instrument relative isolate flex items-center gap-3.5 px-4 py-3.5"><Watermark icon="games" at="right" size={124} rotate={-14} opacity={.05} />
      {active && <Artwork entry={active} />}
      <div className="min-w-0 flex-1"><p className="eyebrow">Game session</p><h2 className="mt-1.5 truncate text-[15px] font-semibold leading-tight text-text-primary">{active?.name ?? `Place ${current.place_id}`}</h2><p className="mt-1 text-[11.5px] leading-snug text-text-muted">{gameSessionDescription(current, tunnelState === "connected" ? route : null)}</p></div>
      <p className="hidden shrink-0 items-center gap-2 font-mono text-[10px] uppercase tracking-[.1em] text-text-muted min-[950px]:flex"><span className={`h-1.5 w-1.5 rounded-full ${tunnelState === "connected" ? "bg-status-connected" : "bg-text-dimmed"}`} />{tunnelState === "connected" ? "Tunnel active" : "Current connection"}</p>
    </section>}
    <div data-search-anchor="games_library" className="flex flex-wrap items-center gap-2">
      <div className="flex items-center gap-0.5">{(["all", "favourites"] as const).map(value => <button key={value} type="button" aria-pressed={filter === value} className={`h-[30px] rounded-[var(--radius-button)] px-3 text-[11.5px] font-medium transition-colors ${filter === value ? "bg-bg-active text-text-primary" : "text-text-muted hover:text-text-primary"}`} onClick={() => setFilter(value)}>{value === "all" ? "Recent & saved" : "Favourites"}</button>)}</div>
      <label className="relative min-w-[170px] flex-1"><Icon name="search" size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" /><input aria-label="Find a saved game" placeholder="Find a game" value={query} onChange={e => setQuery(e.target.value)} className="h-[30px] w-full rounded-[var(--radius-input)] border border-border-subtle bg-bg-card pl-8 pr-3 text-[11.5px] text-text-primary outline-none transition-colors placeholder:text-text-dimmed focus-visible:border-border-focus" /></label>
      <Button data-search-anchor="games_add" size="sm" variant="secondary" disabled={locked || !library} onClick={() => { setError(null); setAdding(true); }}>Add game</Button>
      <button type="button" title="Refresh games" aria-label="Refresh games" disabled={locked || loading} className={iconButtonClass} onClick={() => void run(() => gamesRefreshMetadata())}><Icon name="refresh" size={14} /></button>
    </div>
    {!library && loading && <div className="grid grid-cols-2 gap-3" aria-label="Loading games">{[1,2,3,4].map(i => <div key={i} className="h-[122px] animate-pulse rounded-[var(--radius-card)] bg-bg-card" />)}</div>}
    {library && !entries.length && <EmptyState icon={<Icon name="games" size={18} strokeWidth={1.8} style={{ color: "var(--color-text-muted)" }} />} title="Your next game starts here." description="Join a game with SwiftTunnel open, or add a favourite above. Keep a small library of the games you actually play." />}
    {library && !!entries.length && !shown.length && <p className="py-10 text-center text-[12px] text-text-muted">No games match this view.</p>}
    {!!shown.length && <div data-search-anchor="games_cards" className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] gap-3">{shown.map(entry => {
      const preferences = defaultGamePreferences(entry);
      return <article key={`${entry.client}:${entry.place_id}`} className="instrument flex flex-col gap-3.5 p-3.5">
        <div className="flex items-start gap-3"><Artwork entry={entry} /><div className="min-w-0 flex-1"><h3 className="line-clamp-2 text-[13.5px] font-semibold leading-snug text-text-primary" title={entry.name}>{entry.name}</h3><p className="mt-1 text-[11px] text-text-muted">{entry.client === "vng" ? "Roblox VNG" : "Roblox"}{entry.last_played ? ` · ${new Date(entry.last_played * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" })}` : " · Saved"}</p><p className="mt-1 text-[10.5px] text-text-dimmed">{preferences.fps_cap ? `${preferences.fps_cap === 99999 ? "Uncapped" : `${preferences.fps_cap} FPS`} · ` : ""}{preferences.datacenter_id ? "Preferred region" : preferences.use_tunnel ? "Automatic connection" : "Use current connection"}</p></div>
          <button type="button" aria-label={`${entry.favourite ? "Remove" : "Add"} ${entry.name} ${entry.favourite ? "from" : "to"} favourites`} aria-pressed={entry.favourite} disabled={locked || !!loadError} className={`${iconButtonClass} -mr-1 -mt-1 ${entry.favourite ? "!text-text-primary" : ""}`} onClick={() => void run(() => gamesSetFavourite(entry.place_id, entry.client, !entry.favourite))}><Star filled={entry.favourite} /></button></div>
        <div className="flex items-center gap-1.5"><Button size="sm" className="min-w-[92px]" disabled={locked} onClick={() => void prepare(entry)}>Play</Button>
          {entry.job_id && entry.client === "standard" && <Button size="sm" variant="secondary" disabled={locked} onClick={() => void prepare(entry, entry.job_id, null, false)}>Rejoin</Button>}
          <span className="flex-1" />
          <button type="button" title="Game settings" aria-label={`Settings for ${entry.name}`} disabled={locked} className={iconButtonClass} onClick={() => setProfile(entry)}><Icon name="settings" size={15} /></button>
          <ActionMenu label={`More actions for ${entry.name}`}>
            {entry.client === "standard" && <><button type="button" disabled={locked} className={`${menuItemClass} text-text-secondary`} onClick={()=>void prepare(entry,null,null,false,true)}>Safe launch (no FastFlags)</button><button type="button" disabled={locked} className={`${menuItemClass} text-text-secondary`} onClick={()=>void run(async()=>{const path=await gamesCreateShortcut(entry.place_id,entry.name);setNotice(`Game shortcut saved: ${path}`);})}>Create game shortcut</button></>}
            {entry.client === "standard" && <><button type="button" disabled={locked} className={`${menuItemClass} text-text-secondary hover:text-text-primary`} onClick={() => setServers(entry)}>Find server</button><button type="button" disabled={locked} className={`${menuItemClass} text-text-secondary hover:text-text-primary`} onClick={() => void run(() => navigator.clipboard.writeText(gameShareUrl(entry.place_id, entry.job_id)), "Join link copied.")}>Copy link</button></>}
            <button type="button" disabled={locked || !!loadError} className={`${menuItemClass} text-status-error`} onClick={() => setRemove(entry)}>Forget game</button>
          </ActionMenu>
        </div>
      </article>;
    })}</div>}
    {library && <section className="instrument"><Row anchorId="join_notifications" label="Join notifications" desc="Show the detected server and its verified estimate once per join."><Toggle enabled={library.notify_joins} disabled={locked || !!loadError} ariaLabel="Server information notification" onChange={enabled => void run(() => gamesSetNotifications(enabled))} /></Row></section>}
    <GamePreferencesDialog entry={profile} onClose={() => setProfile(null)} onSaved={() => void refresh()} />
    <Dialog open={!!suggestion} onClose={()=>setSuggestion(null)} title="Matchmaker found another datacenter" description="This location matches your Matchmaker preferences. Moving will leave this game. If you do nothing for 20 seconds, you stay here."><div className="flex justify-end gap-2"><Button size="sm" variant="secondary" onClick={()=>setSuggestion(null)}>Stay here</Button><Button size="sm" onClick={()=>{if(suggestion&&active){const chosen=suggestion;setSuggestion(null);void prepare(active,chosen.job_id,chosen.datacenter?.id??null,false);}}}>Review {suggestion?.datacenter?.city}</Button></div></Dialog>
    <section className="instrument"><button type="button" className="flex w-full items-center justify-between px-3.5 py-3 text-left" aria-expanded={reportsOpen} onClick={()=>setReportsOpen(v=>!v)}><span className="eyebrow">Session reports & diagnostics</span><Icon name="chevron-right" size={12} className={reportsOpen?"rotate-90":""}/></button>{reportsOpen&&<div className="border-t border-border-subtle p-3"><SessionReportsPanel/></div>}</section>
    <Dialog open={!!library?.recovery} onClose={()=>void run(()=>gamesDismissRecovery())} title="Roblox closed unexpectedly" description="SwiftTunnel saw the player exit without a game-leave event. This can also happen after Force close. Rejoin is optional; server availability is checked again."><div className="flex justify-end gap-2"><Button size="sm" variant="secondary" onClick={()=>void run(()=>gamesDismissRecovery())}>Stay closed</Button><Button size="sm" disabled={busy} onClick={()=>{const previous=library?.recovery;const entry=entries.find(e=>e.place_id===previous?.place_id&&e.client===previous.client);if(entry&&previous){void gamesDismissRecovery().then(()=>prepare(entry,previous.job_id,null,false));}}}>Review rejoin</Button></div></Dialog>
    <GameServerDialog entry={servers} onClose={() => setServers(null)} onJoin={(entry, server, center) => { setServers(null); void prepare(entry, server.job_id, center.id, false); }} />
    <Dialog open={adding} onClose={() => { if (!busy) setAdding(false); }} title="Add a game" description="Paste its official Roblox game link or place ID. No Roblox sign-in is needed here.">
      <form onSubmit={e => { e.preventDefault(); void addFavourite(); }} className="flex flex-col gap-4">{error && <ErrorBanner tone="error">{error}</ErrorBanner>}<input autoFocus aria-label="Roblox game link or place ID" value={input} onChange={e => setInput(e.target.value)} maxLength={2048} placeholder="https://www.roblox.com/games/..." disabled={busy} className={fieldClass} /><div className="flex justify-end gap-2"><Button type="button" size="sm" variant="secondary" disabled={busy} onClick={() => setAdding(false)}>Cancel</Button><Button type="submit" size="sm" loading={busy} disabled={!input.trim()}>Add favourite</Button></div></form>
    </Dialog>
    <Dialog open={!!review} onClose={() => { if (!busy) setReview(null); }} title={review?.blocked ? "That server is unavailable" : review?.running ? "Ready to change games?" : "Join this server?"}
      description={review?.blocked ? "It is full or no longer listed. You can join the game normally instead." : review?.running ? review.plan.needs_close ? "Your current Roblox client will close so its settings and route can be prepared safely." : "This may leave your current game." : "Current availability could not be verified. Roblox may report that it is full or closed."}>
      <div className="flex flex-col gap-4"><div className="rounded-[10px] bg-bg-base px-3.5 py-3"><p className="text-[12.5px] font-semibold text-text-primary">{review?.entry.name}</p>{review?.plan.datacenter && <p className="mt-1 text-[11px] text-text-muted">{review.plan.datacenter.city}, {review.plan.datacenter.country}</p>}</div>{error && <ErrorBanner tone="error">{error}</ErrorBanner>}<div className="flex flex-wrap justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy} onClick={() => setReview(null)}>Cancel</Button>
        <Button size="sm" variant={review?.blocked ? "primary" : "secondary"} disabled={busy} onClick={() => { if (review) { const entry = review.entry; setReview(null); void prepare(entry, null, null, false); } }}>Play normally</Button>
        {!review?.blocked && <Button size="sm" loading={busy} onClick={() => { if (review) void launch(review.entry, review.plan, review.running && review.plan.needs_close, review.safe); }}>{review?.running && review.plan.needs_close ? "Close Roblox & play" : "Join server"}</Button>}</div></div>
    </Dialog>
    <Dialog open={!!remove} onClose={() => { if (!busy) setRemove(null); }} title="Forget this game?" description="Removes its local history, profile and favourite. Your Roblox account is unchanged."><div className="flex justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy} onClick={() => setRemove(null)}>Cancel</Button><Button size="sm" variant="destructive" loading={busy} onClick={() => { if (remove) void run(async () => { await gamesForget(remove.place_id, remove.client); setRemove(null); }); }}>Forget</Button></div></Dialog>
  </div>;
}
