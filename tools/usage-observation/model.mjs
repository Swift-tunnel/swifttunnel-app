// Privacy/schema checks and offline models. Nothing here can forward or drop a packet.
const hex = (value, n) =>
  typeof value === "string" && new RegExp(`^[0-9a-f]{${n}}$`).test(value);
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const requireValue = (value, message) => {
  if (!value) throw Error(message);
};
function keys(object, allowed) {
  requireValue(
    object && typeof object === "object" && !Array.isArray(object),
    "Expected object",
  );
  for (const key of Object.keys(object))
    requireValue(allowed.includes(key), "Unrecognised measurement field");
}
export function validateRecord(row) {
  requireValue(
    row?.schema === 1 && hex(row.campaign, 32),
    "Invalid campaign/schema",
  );
  if (row.kind === "campaign_relays") {
    keys(row, ["schema", "kind", "campaign", "relays", "interval_ms"]);
    requireValue(
      Array.isArray(row.relays) &&
        row.relays.length > 0 &&
        row.relays.length <= 64 &&
        new Set(row.relays).size === row.relays.length &&
        row.relays.every((x) => /^[a-z0-9-]{1,64}$/.test(x)),
      "Invalid relay manifest",
    );
    requireValue(
      integer(row.interval_ms) &&
        row.interval_ms >= 5000 &&
        row.interval_ms <= 60000,
      "Invalid manifest interval",
    );
    return;
  }
  if (row.kind === "observer_summary") {
    keys(row, [
      "schema",
      "kind",
      "campaign",
      "session",
      "samples",
      "wall_ms",
      "cpu_ms",
    ]);
    requireValue(
      hex(row.session, 32) &&
        integer(row.samples) &&
        integer(row.wall_ms) &&
        Number.isFinite(row.cpu_ms) &&
        row.cpu_ms >= 0,
      "Invalid observer summary",
    );
    return;
  }
  requireValue(integer(row.unix_ms) && row.unix_ms > 0, "Invalid sample time");
  requireValue(
    integer(row.interval_ms) &&
      row.interval_ms >= 5000 &&
      row.interval_ms <= 60000,
    "Invalid interval",
  );
  requireValue(typeof row.valid === "boolean", "Missing coverage validity");
  if (row.kind === "desktop") {
    keys(row, [
      "schema",
      "kind",
      "campaign",
      "account",
      "device",
      "session",
      "unix_ms",
      "mono_ms",
      "interval_ms",
      "valid",
      "players",
      "players_with_udp",
      "studio",
      "helpers",
      "studio_descendant_players",
      "process_error",
      "udp4_error",
      "udp6_error",
      "sample_wall_ms",
    ]);
    requireValue(
      hex(row.account, 64) &&
        hex(row.device, 64) &&
        hex(row.session, 32) &&
        integer(row.mono_ms),
      "Invalid desktop identity",
    );
    requireValue(
      Number.isFinite(row.sample_wall_ms) && row.sample_wall_ms >= 0,
      "Invalid observer duration",
    );
    for (const k of ["process_error", "udp4_error", "udp6_error"])
      requireValue(integer(row[k]), "Invalid error code");
    for (const k of [
      "players",
      "studio",
      "helpers",
      "studio_descendant_players",
    ])
      requireValue(
        row.valid ? integer(row[k]) && row[k] <= 32768 : row[k] === null,
        "Invalid counts",
      );
    requireValue(
      row.players_with_udp === null ||
        (row.valid &&
          integer(row.players_with_udp) &&
          row.players_with_udp <= row.players),
      "Invalid UDP owner count",
    );
    if (row.valid)
      requireValue(
        row.studio_descendant_players <= row.players,
        "Invalid Studio count",
      );
    return;
  }
  requireValue(row.kind === "relay", "Unknown record type");
  keys(row, [
    "schema",
    "kind",
    "campaign",
    "relay",
    "interval_ms",
    "unix_ms",
    "valid",
    "error",
    "run_id",
    "accounts",
    "busy_accounts",
    "account_count",
    "truncated",
    "collection_ms",
    "return_sessions",
    "busy_return_sessions",
    "return_sessions_truncated",
  ]);
  requireValue(
    typeof row.relay === "string" &&
      /^[a-z0-9-]{1,64}$/.test(row.relay) &&
      Number.isFinite(row.collection_ms) &&
      row.collection_ms >= 0,
    "Invalid relay",
  );
  if (!row.valid) {
    requireValue(
      typeof row.error === "string" && /^[A-Za-z0-9_]+$/.test(row.error),
      "Missing failure coverage",
    );
    return;
  }
  requireValue(
    hex(row.run_id, 32) &&
      Array.isArray(row.accounts) &&
      row.accounts.length <= 4096 &&
      integer(row.busy_accounts) &&
      integer(row.account_count) &&
      typeof row.truncated === "boolean",
    "Invalid relay coverage",
  );
  const identities = new Set();
  for (const a of row.accounts) {
    keys(a, [
      "account",
      "epoch",
      "sample_mono_ms",
      "offered",
      "new_flows",
      "budget_dropped_packets",
    ]);
    requireValue(
      hex(a.account, 64) &&
        !identities.has(a.account) &&
        integer(a.epoch) &&
        integer(a.sample_mono_ms) &&
        integer(a.new_flows) &&
        integer(a.budget_dropped_packets),
      "Invalid counter identity",
    );
    requireValue(
      Array.isArray(a.offered) &&
        a.offered.length === 4 &&
        a.offered.every(integer),
      "Invalid offered counters",
    );
    identities.add(a.account);
  }
  requireValue(
    Array.isArray(row.return_sessions) &&
      row.return_sessions.length <= 4096 &&
      integer(row.busy_return_sessions) &&
      typeof row.return_sessions_truncated === "boolean",
    "Invalid return coverage",
  );
  const sessions = new Set();
  for (const a of row.return_sessions) {
    keys(a, [
      "account",
      "session",
      "created_at",
      "sample_mono_ms",
      "frame_bytes_out",
      "packets_out",
    ]);
    requireValue(
      hex(a.account, 64) &&
        hex(a.session, 64) &&
        !sessions.has(a.session) &&
        integer(a.created_at) &&
        integer(a.sample_mono_ms) &&
        integer(a.frame_bytes_out) &&
        integer(a.packets_out),
      "Invalid successful-return counters",
    );
    requireValue(
      integer(a.frame_bytes_out + 28 * a.packets_out),
      "Unsafe IPv4 return estimate",
    );
    sessions.add(a.session);
  }
}
export function contiguous(a, b, mono = "mono_ms") {
  const wall = b.unix_ms - a.unix_ms,
    elapsed = b[mono] - a[mono];
  return (
    wall > 0 &&
    elapsed > 0 &&
    elapsed <= 1.5 * a.interval_ms &&
    a.interval_ms === b.interval_ms &&
    Math.abs(wall - elapsed) <= 1000
  );
}
export function intersect(a, b) {
  const result = [];
  let i = 0,
    j = 0;
  while (i < a.length && j < b.length) {
    const lo = Math.max(a[i][0], b[j][0]),
      hi = Math.min(a[i][1], b[j][1]);
    if (hi > lo) result.push([lo, hi]);
    if (a[i][1] < b[j][1]) i++;
    else j++;
  }
  return result;
}
export function relayCoverage(records) {
  const ranges = [];
  let prev;
  for (const row of records) {
    if (
      prev &&
      prev.valid &&
      row.valid &&
      prev.run_id === row.run_id &&
      !prev.busy_accounts &&
      !row.busy_accounts &&
      !prev.truncated &&
      !row.truncated &&
      prev.accounts.length === prev.account_count &&
      row.accounts.length === row.account_count &&
      row.unix_ms > prev.unix_ms &&
      row.unix_ms - prev.unix_ms <= 1.5 * prev.interval_ms
    ) {
      const last = ranges.at(-1);
      if (last && last[1] === prev.unix_ms) last[1] = row.unix_ms;
      else ranges.push([prev.unix_ms, row.unix_ms]);
    }
    prev = row;
  }
  return ranges;
}
export function desktopIntervals(records) {
  const previous = new Map(),
    intervals = [];
  for (const row of records) {
    const key = row.device + ":" + row.session,
      prev = previous.get(key);
    if (prev?.valid && row.valid && contiguous(prev, row))
      intervals.push({
        start: prev.unix_ms,
        end: row.unix_ms,
        device: row.device,
        session: row.session,
        players: prev.players,
        studio: prev.studio,
        studioPlayers: prev.studio_descendant_players,
      });
    previous.set(key, row);
  }
  return intervals;
}
export function trafficIntervals(records) {
  const previous = new Map(),
    intervals = [],
    gaps = [];
  let knownBytes = 0,
    unalignedBytes = 0,
    baselines = 0;
  for (const row of records) {
    const prev = previous.get(row.relay);
    previous.set(row.relay, row);
    if (!prev) {
      baselines++;
      gaps.push([row.unix_ms - 1.5 * row.interval_ms, row.unix_ms]);
      continue;
    }
    const same = prev.run_id === row.run_id && prev.epoch === row.epoch;
    const diff = row.offered.map((v, i) => v - prev.offered[i]);
    if (!same || diff.some((v) => v < 0) || row.new_flows < prev.new_flows) {
      baselines++;
      gaps.push([prev.unix_ms, row.unix_ms]);
      continue;
    }
    const bytes = diff[1] + diff[3];
    requireValue(integer(bytes), "Unsafe traffic total");
    knownBytes += bytes;
    if (!contiguous(prev, row, "sample_mono_ms")) {
      unalignedBytes += bytes;
      gaps.push([prev.unix_ms, row.unix_ms]);
      continue;
    }
    intervals.push({
      start: prev.unix_ms,
      end: row.unix_ms,
      rate: bytes / (row.unix_ms - prev.unix_ms),
      bytes,
    });
  }
  return { intervals, gaps, knownBytes, unalignedBytes, baselines };
}
export function evaluate(
  desktop,
  traffic,
  coverage,
  { rates = [5, 10, 20], burstBytes = 256 * 1024 * 1024, graceMs = 90000 } = {},
) {
  const events = [];
  for (const d of desktop) {
    events.push(
      { t: d.start, type: "desktop", delta: 1, value: d },
      { t: d.end, type: "desktop", delta: -1, value: d },
    );
  }
  for (const n of traffic.intervals)
    events.push(
      { t: n.start, type: "traffic", delta: n.rate },
      { t: n.end, type: "traffic", delta: -n.rate },
    );
  for (const g of traffic.gaps)
    if (g[1] > g[0])
      events.push(
        { t: g[0], type: "gap", delta: 1 },
        { t: g[1], type: "gap", delta: -1 },
      );
  for (const [start, end] of coverage)
    events.push(
      { t: start, type: "coverage", delta: 1 },
      { t: end, type: "coverage", delta: -1 },
    );
  events.sort((a, b) => a.t - b.t);
  const devices = new Map(),
    models = rates.map((mbps) => ({
      mbps,
      cap: (mbps * 1e6) / 8 / 1000,
      tokens: burstBytes,
      modelled_excess_bytes: 0,
      complete_60s_windows: 0,
      windows_over_rate: 0,
    }));
  const result = {
    observed_ms: 0,
    multi_ms: 0,
    over_grace_ms: 0,
    over_grace_with_studio_ms: 0,
    max_players: 0,
    duplicate_device_ms: 0,
    offered_bytes_single: 0,
    offered_bytes_multi: 0,
    offered_bytes_zero_players: 0,
    offered_bytes_without_desktop: 0,
    rate_model_covered_ms: 0,
    rate_model_excluded_ms: 0,
  };
  let at = events[0]?.t ?? 0,
    rate = 0,
    covered = 0,
    gaps = 0,
    streak = 0,
    windowMs = 0,
    windowBytes = 0;
  const segment = (end) => {
    const duration = end - at;
    if (duration <= 0) return;
    let players = 0,
      studio = false,
      duplicate = false;
    for (const entries of devices.values()) {
      if (entries.size !== 1) {
        duplicate = true;
        continue;
      }
      const d = [...entries][0];
      players += d.players;
      studio ||= d.studio > 0 || d.studioPlayers > 0;
    }
    const hasDesktop = devices.size > 0 && !duplicate;
    const bytes = Math.max(0, rate) * duration;
    if (duplicate) result.duplicate_device_ms += duration;
    if (hasDesktop) {
      result.observed_ms += duration;
      result.max_players = Math.max(result.max_players, players);
      if (players >= 2) {
        result.multi_ms += duration;
        const old = streak;
        streak += duration;
        const over = Math.max(0, streak - graceMs) - Math.max(0, old - graceMs);
        result.over_grace_ms += over;
        if (studio) result.over_grace_with_studio_ms += over;
      } else streak = 0;
    } else streak = 0;
    if (hasDesktop && players >= 2) result.offered_bytes_multi += bytes;
    else if (hasDesktop && players === 1) result.offered_bytes_single += bytes;
    else if (hasDesktop) result.offered_bytes_zero_players += bytes;
    else result.offered_bytes_without_desktop += bytes;
    if (covered > 0 && gaps === 0) {
      result.rate_model_covered_ms += duration;
      for (const m of models) {
        const demand = (Math.max(0, rate) - m.cap) * duration;
        if (demand > 0) {
          m.modelled_excess_bytes += Math.max(0, demand - m.tokens);
          m.tokens = Math.max(0, m.tokens - demand);
        } else m.tokens = Math.min(burstBytes, m.tokens - demand);
      }
      let remaining = duration;
      while (remaining > 0) {
        const step = Math.min(remaining, 60000 - windowMs);
        windowMs += step;
        windowBytes += Math.max(0, rate) * step;
        remaining -= step;
        if (windowMs === 60000) {
          for (const m of models) {
            m.complete_60s_windows++;
            if (windowBytes > m.cap * 60000) m.windows_over_rate++;
          }
          windowMs = 0;
          windowBytes = 0;
        }
      }
    } else {
      result.rate_model_excluded_ms += duration;
      windowMs = 0;
      windowBytes = 0;
      for (const m of models) m.tokens = burstBytes;
    }
  };
  for (let i = 0; i < events.length;) {
    const t = events[i].t;
    segment(t);
    at = t;
    while (i < events.length && events[i].t === t) {
      const e = events[i++];
      if (e.type === "traffic") rate += e.delta;
      else if (e.type === "coverage") covered += e.delta;
      else if (e.type === "gap") gaps += e.delta;
      else {
        const entries = devices.get(e.value.device) ?? new Set();
        if (e.delta > 0) entries.add(e.value);
        else entries.delete(e.value);
        if (entries.size) devices.set(e.value.device, entries);
        else devices.delete(e.value.device);
      }
    }
  }
  result.rate_models = models.map(
    ({
      mbps,
      modelled_excess_bytes,
      complete_60s_windows,
      windows_over_rate,
    }) => ({
      mbps,
      modelled_excess_bytes: Math.round(modelled_excess_bytes),
      complete_60s_windows,
      windows_over_rate,
    }),
  );
  return result;
}
