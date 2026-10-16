import type { GameRouteStatus, RobloxClient, RobloxGameSession, RobloxGameEntry, RobloxServerPage } from "./types";

export function appendServerPage(previous: RobloxServerPage, incoming: RobloxServerPage): RobloxServerPage {
  const servers = new Map(previous.servers.map(server => [server.job_id, server]));
  for (const server of incoming.servers) {
    if (servers.has(server.job_id) || servers.size < 200) servers.set(server.job_id, server);
  }
  return {
    ...incoming,
    // A repeated cursor would keep offering the very same page forever.
    next_cursor: incoming.next_cursor === previous.next_cursor ? null : incoming.next_cursor,
    servers: [...servers.values()],
  };
}

export const gameEntryKey = (entry: RobloxGameEntry): string =>
  `${entry.client}:${entry.universe_id ? `universe:${entry.universe_id}` : `place:${entry.place_id}`}`;

export const gamePlayPlace = (entry: RobloxGameEntry, specificServer = false): string =>
  specificServer ? entry.place_id : entry.root_place_id ?? entry.place_id;

/** One card per experience, keeping the latest place and job for Rejoin. */
export function gameLibraryEntries(entries: RobloxGameEntry[], view: "all" | "favourites", query: string): RobloxGameEntry[] {
  const groups = new Map<string, RobloxGameEntry>();
  for (const entry of [...entries].sort((a, b) => (b.last_played ?? 0) - (a.last_played ?? 0))) {
    const key = gameEntryKey(entry);
    const existing = groups.get(key);
    if (!existing) groups.set(key, { ...entry });
    else {
      existing.favourite ||= entry.favourite;
      existing.icon_url ??= entry.icon_url;
    }
  }
  const filtered = [...groups.values()].filter(entry => (view !== "favourites" || entry.favourite)
    && `${entry.name} ${entry.place_id}`.toLowerCase().includes(query.trim().toLowerCase()));
  return view === "all" ? filtered.slice(0, 4) : filtered;
}

export function gameLinkClient(input: string): RobloxClient | null {
  try {
    const url = new URL(input.trim());
    if (url.protocol !== "https:" || url.username || url.password) return null;
    if (["robloxapp.vnggames.com", "www.robloxapp.vnggames.com"].includes(url.hostname)) return "vng";
    if (["roblox.com", "www.roblox.com"].includes(url.hostname)) return "standard";
  } catch { /* A numeric place ID keeps the selected client. */ }
  return null;
}

export function parsePlaceInput(input: string): string | null {
  let id = input.trim();
  if (!/^\d+$/.test(id)) {
    try {
      const url = new URL(id);
      if (!gameLinkClient(input)) return null;
      id = /^\/games\/(\d+)(?:\/|$)/.exec(url.pathname)?.[1] ?? "";
    } catch { return null; }
  }
  if (!/^[1-9]\d{0,18}$/.test(id) || BigInt(id) > 9223372036854775807n) return null;
  return id;
}

// Location and estimate must describe this exact game destination. A selected
// relay or a picker reference is not proof of the server the player joined.
export function gameSessionDescription(session: RobloxGameSession | null, route: GameRouteStatus | null): string {
  if (!session) return "Join a Roblox game to see its server information.";
  if (!route || route.game_server_ip !== session.ip) return session.location
    ? `Roblox ${session.location}${session.location_source === "ip_location" ? " · Approximate location" : ""}`
    : "Game detected. Server location unknown.";
  if (route.bypassed) return `Roblox ${route.game_location} · Direct connection`;
  const ping = route.estimated_path_ms;
  return `Roblox ${route.game_location}${ping !== null && Number.isFinite(ping) && ping >= 0 ? ` · ~${Math.round(ping)} ms` : ""}`;
}

export function gameShareUrl(placeId: string, jobId: string | null, client: RobloxClient = "standard"): string {
  const url = new URL(client === "vng" ? "https://www.robloxapp.vnggames.com/games/start" : "https://www.roblox.com/games/start");
  url.searchParams.set("placeId", placeId);
  if (jobId) url.searchParams.set("gameInstanceId", jobId);
  return url.toString();
}
