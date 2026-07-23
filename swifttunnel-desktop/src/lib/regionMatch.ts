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

/**
 * Return a valid region id for a possibly-stale saved `selected`, or `null` when
 * it is already valid and canonical (nothing to change).
 *
 * Keeps a user's saved region usable across a server-list change — e.g. a full
 * relay-fleet swap. A legacy/suffixed id that still maps to a region (via
 * {@link findRegionForVpnRegion}, which prefix-matches "singapore-03" ->
 * "singapore") is normalized to that region's canonical id; a region that no
 * longer exists at all falls back to the lowest-latency available region, or the
 * first one in the list when no latencies are known yet.
 */
export function resolveValidRegion(
  regions: ServerRegion[],
  selected: string | null,
  latencies?: Map<string, number | null>,
): string | null {
  if (regions.length === 0) return null;

  const match = findRegionForVpnRegion(regions, selected);
  if (match) {
    return match.id === selected ? null : match.id;
  }

  // Stale/unknown region → closest one we can measure, else the first.
  let best = regions[0];
  let bestLatency = Number.POSITIVE_INFINITY;
  if (latencies) {
    for (const region of regions) {
      const latency = latencies.get(region.id);
      if (typeof latency === "number" && latency >= 0 && latency < bestLatency) {
        bestLatency = latency;
        best = region;
      }
    }
  }
  return best.id;
}

