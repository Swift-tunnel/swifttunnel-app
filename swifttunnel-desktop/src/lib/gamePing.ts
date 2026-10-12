import type { ServerInfo, ReferenceEstimate } from "./types";

// The core selects each relay's own regional reference. Endpoint and freshness
// checks prevent a reused relay id or expired measurement from leaking through.
export function relayReferenceEstimate(server: ServerInfo | undefined, previews: ReferenceEstimate[] = []) {
  if (!server?.relay_available) return undefined;
  const address = `${server.ip}:${server.relay_port ?? 51821}`;
  return previews.find(row => row.relay === server.region && row.address === address && row.expiresAt > performance.now());
}

export function regionGameEstimate(ids: string[], servers: ServerInfo[], previews: ReferenceEstimate[] = []) {
  const values = servers.filter(server => ids.includes(server.region)).flatMap(server => {
    const row = relayReferenceEstimate(server, previews);
    return row ? [row.estimated_game_ms] : [];
  });
  return values.length ? Math.min(...values) : null;
}
