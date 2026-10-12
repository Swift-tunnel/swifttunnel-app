import type { GameRouteStatus, ServerInfo, ReferenceEstimate } from "./types";

// A relay id may be reused for a different box. Never carry its old estimate over.
export function relayGameEstimate(route: GameRouteStatus | null | undefined, server: ServerInfo | undefined, previews: ReferenceEstimate[] = []) {
  if (route?.bypassed || !server?.relay_available) return undefined;
  const address = `${server.ip}:${server.relay_port ?? 51821}`;
  // Once a real game is known, never mix references into its comparison.
  return route ? route.relay_estimates?.find(row => row.relay === server.region && row.address === address)
    : previews.find(row => row.relay === server.region && row.address === address && row.expiresAt > performance.now());
}

export function regionGameEstimate(route: GameRouteStatus | null | undefined, ids: string[], servers: ServerInfo[], previews: ReferenceEstimate[] = []) {
  const values = servers.filter(server => ids.includes(server.region))
    .flatMap(server => {
      const row = relayGameEstimate(route, server, previews);
      return row ? [row.estimated_game_ms] : [];
    });
  return values.length ? Math.min(...values) : null;
}
