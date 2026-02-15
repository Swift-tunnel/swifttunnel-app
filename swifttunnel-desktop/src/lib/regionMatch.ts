import type { ServerRegion } from "./types";

/**
 * Best-effort mapping from the VPN's reported region string to a ServerRegion.
 *
 * `vpnRegion` can be:
 * - a region id (e.g. "singapore")
 * - a server id (e.g. "us-east-nj") after auto-routing switches relays
 * - a display name (e.g. "Singapore") depending on backend/older builds
 */
export function findRegionForVpnRegion(
  regions: ServerRegion[],
  vpnRegion: string | null,
): ServerRegion | undefined {
  const normalized = vpnRegion?.trim().toLowerCase();
  if (!normalized) return undefined;

  // 1) Region id match.
  const byId = regions.find((r) => r.id.toLowerCase() === normalized);
  if (byId) return byId;

  // 2) Server id match (auto-routing may report "us-east-nj", etc).
  const byServerId = regions.find((r) =>
    r.servers.some((id) => id.toLowerCase() === normalized),
  );
  if (byServerId) return byServerId;

  // 3) Display name match.
  const byName = regions.find((r) => r.name.toLowerCase() === normalized);
  if (byName) return byName;

  // 4) Prefix fallback: try progressively shorter prefixes by stripping
  //    the last "-segment" each time. This handles multi-segment names
  //    like "us-east-nj" -> try "us-east" -> try "us".
  const parts = normalized.split("-");
  for (let i = parts.length - 1; i >= 1; i--) {
    const prefix = parts.slice(0, i).join("-");
    const byPrefix = regions.find((r) => r.id.toLowerCase() === prefix);
    if (byPrefix) return byPrefix;
  }

  return undefined;
}

