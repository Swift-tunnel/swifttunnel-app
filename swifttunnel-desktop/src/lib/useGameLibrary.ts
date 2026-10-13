import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useGameLibraryStore } from "../stores/gameLibraryStore";
import { useVpnStore } from "../stores/vpnStore";
import { gameSessionDescription } from "./robloxGames";
import { notify } from "./notifications";
import { reportError } from "./errors";
import { gamesStartupTarget } from "./commands";
import { useDeepLinkStore } from "../stores/deepLinkStore";
let startupRequestSent=false;
let startupTargetPromise:Promise<string|null>|null=null;

export function useGameLibrary() {
  useEffect(()=>{
    let disposed=false;let stop:(()=>void)|undefined;
    const open=(action:string)=>{if(disposed)return;useGameLibraryStore.getState().requestAction(action);useDeepLinkStore.getState().navigateTo({tab:"games",anchor:"games_library"});};
    void listen<string>("games-open",event=>{if(event.payload.startsWith("play:")){void gamesStartupTarget().then(place=>open(place?`play:${place}`:event.payload)).catch(()=>open(event.payload));}else{open(event.payload);}}).then(fn=>{if(disposed)fn();else stop=fn;}).catch(e=>reportError("Game tray controls",e));
    void (startupTargetPromise??=gamesStartupTarget()).then(place=>{if(!disposed&&place&&!startupRequestSent){startupRequestSent=true;open(`play:${place}`);}}).catch(()=>{});
    return()=>{disposed=true;stop?.();};
  },[]);
  const current = useGameLibraryStore(s => s.library?.current);
  const notified = useRef<string | null>(null);
  useEffect(() => {
    let disposed = false;
    let stop: (() => void) | undefined;
    void listen("roblox-library-changed", () => {
      if (!disposed) void useGameLibraryStore.getState().refresh();
    }).then(unlisten => {
      if (disposed) unlisten(); else stop = unlisten;
    }).catch(error => reportError("Could not subscribe to game-library updates", error));
    return () => { disposed = true; stop?.(); };
  }, []);

  useEffect(() => {
    if (!current) { notified.current = null; return; }
    const key = `${current.client}:${current.place_id}:${current.job_id}:${current.observed_at}`;
    if (notified.current === key) return;
    // Opt-in; toggling the preference doesn't replay an old join.
    notified.current = key;
    if (!current.fresh_join || !useGameLibraryStore.getState().library?.notify_joins) return;
    let disposed = false;
    let attempts = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const show = async () => {
      await useVpnStore.getState().fetchState();
      if (disposed) return;
      const route = useVpnStore.getState().gameRoute;
      const latest = useGameLibraryStore.getState().library?.current;
      if ((!route || route.game_server_ip !== current.ip) && !latest?.location && ++attempts < 5) {
        timer = setTimeout(send, 2000);
        return;
      }
      const library = useGameLibraryStore.getState().library;
      if (!library?.notify_joins) return;
      const entry = library.entries.find(e => e.place_id === current.place_id && e.client === current.client);
      await notify(entry?.name ?? "Roblox game joined", gameSessionDescription(latest ?? current, route));
    };
    const send = () => { void show().catch(error => reportError("Could not show game notification", error, { dedupeKey: "game-join-notification" })); };
    timer = setTimeout(send, 2000);
    return () => { disposed = true; clearTimeout(timer); };
  }, [current?.place_id, current?.job_id, current?.client, current?.ip, current?.fresh_join, current?.observed_at]);
}
