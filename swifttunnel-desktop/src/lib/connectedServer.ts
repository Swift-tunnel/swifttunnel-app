import type { ServerInfo } from "./types";

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
    return fallbackRegion ?? "Unknown";
  }

  const { host, port } = parseEndpoint(endpoint);

  const exactMatch = servers.find(
    (server) => server.ip === host && (port === null || server.port === port),
  );
  if (exactMatch) {
    return exactMatch.name;
  }

  const ipMatch = servers.find((server) => server.ip === host);
  if (ipMatch) {
    return ipMatch.name;
  }

  return fallbackRegion ?? "Private relay";
}
