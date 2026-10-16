import type { ServerInfo } from "./types";

function displayRelayId(id: string): string {
  return id.split("-").map(part => {
    if (/^(us|uk|uae)$/i.test(part)) return part.toUpperCase();
    return part.charAt(0).toUpperCase() + part.slice(1);
  }).join(" ");
}

function relayLabel(server: ServerInfo): string {
  // API names describe the city and are shared by several relay nodes.
  // Keep the actual node number visible, including when its physical city
  // differs from the region that contains it.
  if (/-\d+$/.test(server.region)) return displayRelayId(server.region);
  // Older server lists used the region as the ID and the node as its name.
  if (/-\d+$/.test(server.name)) return displayRelayId(server.name);
  return server.name || displayRelayId(server.region);
}

function parseEndpoint(endpoint: string): { host: string; port: number | null } {
  const normalized = endpoint.includes("://") ? endpoint : `udp://${endpoint}`;
  try {
    const parsed = new URL(normalized);
    const port = parsed.port ? Number(parsed.port) : null;
    return {
      host: parsed.hostname,
      port: Number.isFinite(port) ? port : null,
    };
  } catch {
    return { host: endpoint.trim(), port: null };
  }
}

export function formatConnectedServerLabel(
  endpoint: string | null,
  servers: ServerInfo[],
  fallbackRegion: string | null,
): string {
  if (!endpoint) {
    return fallbackRegion ? displayRelayId(fallbackRegion) : "Unknown";
  }

  const { host, port } = parseEndpoint(endpoint);

  const exactMatch = servers.find(
    (server) => server.ip === host && port === (server.relay_port ?? 51821),
  );
  if (exactMatch) {
    return relayLabel(exactMatch);
  }

  const ipMatches = servers.filter((server) => server.ip === host);
  if (port === null && ipMatches.length === 1) {
    return relayLabel(ipMatches[0]);
  }

  return fallbackRegion ? displayRelayId(fallbackRegion) : "Private relay";
}
