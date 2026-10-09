import type { GameRouteStatus, ServerInfo } from "./types";

// A relay id may be reused for a different box. Never carry its old estimate over.
export function relayGameEstimate(route: GameRouteStatus | null | undefined, server: ServerInfo | undefined) {
  if (!route || route.bypassed || !server?.relay_available) return undefined;
  const address = `${server.ip}:${server.relay_port ?? 51821}`;
  return route.relay_estimates?.find(row => row.relay === server.region && row.address === address);
}

export function regionGameEstimate(route: GameRouteStatus | null | undefined, ids: string[], servers: ServerInfo[]) {
  const values = servers.filter(server => ids.includes(server.region))
    .flatMap(server => {
      const row = relayGameEstimate(route, server);
      return row ? [row.estimated_game_ms] : [];
    });
  return values.length ? Math.min(...values) : null;
}
