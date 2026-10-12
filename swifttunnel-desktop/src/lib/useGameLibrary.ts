import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useGameLibraryStore } from "../stores/gameLibraryStore";
import { useVpnStore } from "../stores/vpnStore";
import { gameSessionDescription } from "./robloxGames";
import { notify } from "./notifications";
import { reportError } from "./errors";

export function useGameLibrary() {
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
        timer = setTimeout(() => void show(), 2000);
        return;
      }
      const library = useGameLibraryStore.getState().library;
      if (!library?.notify_joins) return;
      const entry = library.entries.find(e => e.place_id === current.place_id && e.client === current.client);
      await notify(entry?.name ?? "Roblox game joined", gameSessionDescription(latest ?? current, route));
    };
    timer = setTimeout(() => void show(), 2000);
    return () => { disposed = true; clearTimeout(timer); };
  }, [current?.place_id, current?.job_id, current?.client, current?.ip, current?.fresh_join, current?.observed_at]);
}
