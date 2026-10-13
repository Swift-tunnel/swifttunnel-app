import type { GameRouteStatus, RobloxGameSession } from "./types";

export function parsePlaceInput(input: string): string | null {
  let id = input.trim();
  if (!/^\d+$/.test(id)) {
    try {
      const url = new URL(id);
      if (url.protocol !== "https:" || !["www.roblox.com", "roblox.com"].includes(url.hostname) || url.username || url.password) return null;
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

export function gameShareUrl(placeId: string, jobId: string | null): string {
  const url = new URL("https://www.roblox.com/games/start");
  url.searchParams.set("placeId", placeId);
  if (jobId) url.searchParams.set("gameInstanceId", jobId);
  return url.toString();
}
