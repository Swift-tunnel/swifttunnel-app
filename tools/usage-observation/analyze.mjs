// Local SQLite only. No network, production database, credentials or account destinations.
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  validateRecord,
  desktopIntervals,
  trafficIntervals,
  relayCoverage,
  intersect,
  evaluate,
} from "./model.mjs";

export async function analyze(
  files,
  outDir,
  { pricePerGb = null, burstBytes = 256 * 1024 * 1024 } = {},
) {
  if (!files.length || files.length > 256)
    throw Error("Provide 1-256 input files");
  if (pricePerGb !== null && (!Number.isFinite(pricePerGb) || pricePerGb < 0))
    throw Error("Invalid explicit marginal price");
  if (/[/\\]OneDrive([/\\]|$)/i.test(path.resolve(outDir)))
    throw Error("Use local audit output outside OneDrive");
  fs.mkdirSync(outDir, { recursive: true });
  const dbPath = path.join(outDir, "observations.sqlite");
  fs.closeSync(fs.openSync(dbPath, "wx", 0o600));
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-8192; PRAGMA temp_store=FILE;
    CREATE TABLE records(id TEXT PRIMARY KEY,kind TEXT,account TEXT,relay TEXT,t INTEGER,body TEXT,digest TEXT);
    CREATE INDEX account_records ON records(account,t);
    CREATE INDEX relay_records ON records(relay,t);
    CREATE TABLE traffic(id TEXT,account TEXT,relay TEXT,t INTEGER,body TEXT,PRIMARY KEY(id,account));
    CREATE INDEX account_traffic ON traffic(account,t);
    CREATE TABLE returns(id TEXT,account TEXT,relay TEXT,t INTEGER,body TEXT,PRIMARY KEY(id,account,relay));
    CREATE INDEX account_returns ON returns(account,t);`);
  const insert = db.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,?)");
  const existing = db.prepare("SELECT digest FROM records WHERE id=?");
  const counter = db.prepare("INSERT INTO traffic VALUES(?,?,?,?,?)");
  const returnCounter = db.prepare("INSERT INTO returns VALUES(?,?,?,?,?)");
  let campaign = null,
    expected = null,
    lineCount = 0,
    desktopCount = 0,
    relayCount = 0,
    invalidCount = 0,
    duplicateRecords = 0;
  const overhead = [];
  const relayQuality = {
    busy_offered_account_samples: 0,
    truncated_offered_snapshots: 0,
    busy_return_session_samples: 0,
    truncated_return_snapshots: 0,
    inconsistent_offered_snapshots: 0,
  };
  let summaries = 0,
    cpuMs = 0,
    wallMs = 0;
  try {
    db.exec("BEGIN");
    for (const file of files) {
      if (fs.statSync(file).size > 256 * 1024 * 1024)
        throw Error("Split inputs into files of at most 256 MiB");
      const input = readline.createInterface({
        input: fs.createReadStream(file, {
          encoding: "utf8",
          highWaterMark: 65536,
        }),
        crlfDelay: Infinity,
      });
      for await (const line of input) {
        if (!line.trim()) continue;
        if (Buffer.byteLength(line) > 4 * 1024 * 1024 || ++lineCount > 10000000)
          throw Error("Analysis size bound reached; split the campaign");
        const row = JSON.parse(line);
        validateRecord(row);
        if (campaign !== null && campaign !== row.campaign)
          throw Error("Do not combine campaigns");
        campaign = row.campaign;
        if (row.kind === "campaign_relays") {
          const ids = [...row.relays].sort();
          if (expected && JSON.stringify(ids) !== JSON.stringify(expected))
            throw Error("Relay inventories differ; analyze separately");
          expected = ids;
          continue;
        }
        const id =
          row.kind === "desktop"
            ? `d:${row.account}:${row.device}:${row.session}:${row.mono_ms}`
            : row.kind === "relay"
              ? `r:${row.relay}:${row.run_id ?? "failed"}:${row.unix_ms}`
              : `s:${row.session}`;
        const body = JSON.stringify(row),
          digest = createHash("sha256").update(body).digest("hex");
        const old = existing.get(id);
        if (old) {
          if (old.digest !== digest)
            throw Error("Conflicting duplicate sample");
          duplicateRecords++;
          continue;
        }
        insert.run(
          id,
          row.kind,
          row.account ?? null,
          row.relay ?? null,
          row.unix_ms ?? 0,
          body,
          digest,
        );
        if (row.kind === "desktop") {
          desktopCount++;
          if (!row.valid) invalidCount++;
          overhead.push(row.sample_wall_ms);
        }
        if (row.kind === "observer_summary") {
          summaries++;
          cpuMs += row.cpu_ms;
          wallMs += row.wall_ms;
        }
        if (row.kind === "relay") {
          relayCount++;
          if (!row.valid) invalidCount++;
          if (row.valid) {
            relayQuality.busy_offered_account_samples += row.busy_accounts;
            relayQuality.truncated_offered_snapshots += Number(row.truncated);
            relayQuality.busy_return_session_samples +=
              row.busy_return_sessions;
            relayQuality.truncated_return_snapshots += Number(
              row.return_sessions_truncated,
            );
            relayQuality.inconsistent_offered_snapshots += Number(
              row.account_count !== row.accounts.length + row.busy_accounts,
            );
          }
          if (row.valid)
            for (const a of row.accounts)
              counter.run(
                id,
                a.account,
                row.relay,
                row.unix_ms,
                JSON.stringify({
                  ...a,
                  relay: row.relay,
                  run_id: row.run_id,
                  unix_ms: row.unix_ms,
                  interval_ms: row.interval_ms,
                }),
              );
          if (row.valid)
            for (const a of row.return_sessions) {
              const identity = row.relay + ":" + a.session;
              returnCounter.run(
                id,
                a.account,
                identity,
                row.unix_ms,
                JSON.stringify({
                  account: a.account,
                  relay: identity,
                  run_id: row.run_id,
                  epoch: a.created_at,
                  unix_ms: row.unix_ms,
                  sample_mono_ms: a.sample_mono_ms,
                  interval_ms: row.interval_ms,
                  offered: [
                    0,
                    0,
                    a.packets_out,
                    a.frame_bytes_out + 28 * a.packets_out,
                  ],
                  new_flows: 0,
                  budget_dropped_packets: 0,
                }),
              );
            }
        }
        if (lineCount % 10000 === 0) db.exec("COMMIT; BEGIN");
      }
    }
    db.exec("COMMIT");
    let coverage = null;
    for (const relay of expected ?? []) {
      const rows = (function* () {
        for (const row of db
          .prepare(
            "SELECT body FROM records WHERE kind='relay' AND relay=? ORDER BY t",
          )
          .iterate(relay))
          yield JSON.parse(row.body);
      })();
      const ranges = relayCoverage(rows);
      coverage = coverage === null ? ranges : intersect(coverage, ranges);
    }
    coverage ??= [];
    const result = {
      schema: 1,
      campaign,
      measurement_only: true,
      clock_alignment_verified: false,
      inputs: {
        records: lineCount,
        desktop_samples: desktopCount,
        relay_samples: relayCount,
        invalid_samples: invalidCount,
        duplicate_records_ignored: duplicateRecords,
        relay_quality: relayQuality,
        expected_relays: expected ?? [],
        fleet_complete_ms: coverage.reduce((n, [a, b]) => n + b - a, 0),
      },
      accounts: {
        with_desktop: 0,
        with_any_observed_player: 0,
        with_relay_counters: 0,
        with_both: 0,
        with_multiple_observed_players: 0,
        with_modelled_multiple_players_across_devices: 0,
        over_90s_modelled_multiple_players: 0,
        too_large_to_analyze: 0,
      },
      observed_account_seconds: 0,
      multiple_player_account_seconds: 0,
      over_90s_account_seconds: 0,
      over_90s_with_studio_present_account_seconds: 0,
      max_observed_players: 0,
      max_modelled_players_across_devices: 0,
      duplicate_device_seconds: 0,
      offered_inner_bytes: {
        known_counter_deltas: 0,
        unaligned: 0,
        during_single_observed_player: 0,
        during_multiple_observed_players: 0,
        during_zero_observed_players: 0,
        without_desktop_observation: 0,
      },
      successful_return_ipv4_bytes: {
        known_counter_deltas: 0,
        unaligned: 0,
        during_multiple_observed_players: 0,
      },
      rate_models: [5, 10, 20].map((mbps) => ({
        mbps,
        accounts_with_modelled_excess: 0,
        modelled_excess_bytes: 0,
        accounts_with_60s_window_over_rate: 0,
        complete_60s_windows: 0,
        windows_over_rate: 0,
      })),
      rate_model_covered_account_seconds: 0,
      rate_model_excluded_account_seconds: 0,
      counter_baselines: 0,
      cost: {
        explicit_marginal_usd_per_gb: pricePerGb,
        modelled_usd_during_multi_player_observation: null,
        modelled_usd_for_successful_return_leg_during_multi_player_observation:
          null,
        extra_instances_cost: null,
        actual_provider_invoice_cost: null,
      },
      limitations: [
        "Opt-in desktop observations describe instrumented clients only, not the whole population or modified clients.",
        "Player processes are counted directly. UDP binding counts are not proof of active gameplay. Studio ancestry is a lower-bound heuristic.",
        "Desktop state is held only between adjacent healthy samples; gaps, overlapping samplers on one device and clock jumps remain unknown. Uninstrumented devices are not inferred.",
        "Cross-device and client/relay correlations require synchronised UTC clocks. Constant clock offsets are not verified by these tools. Maximum observed Players is a single-device count; cross-device totals are modelled separately.",
        "Byte rates assume uniform traffic within each sampled counter interval. Modelled excess bytes are not exact dropped packets, latency predictions or a security enforcement result.",
        "Only fleet-complete coverage is used for rate models. Coverage gaps restart independent model segments; excluded time is not zero usage.",
        "Offered inner-IP counters include failed/dropped attempts and omit encapsulation and kernel retransmissions. Costs are explicit-price scenarios, not provider bills.",
        "Traffic during multi-player observations is the whole account traffic in that period, not causally attributable extra-instance traffic.",
        "Successful client-return estimates use existing send counters plus 28 IPv4/UDP header bytes per datagram. Independent atomics are not a coherent packet pair. The server-facing upload leg, encapsulation variants, link overhead and provider billing differences prevent exact invoices.",
      ],
    };
    const accounts = db.prepare(
      "SELECT account FROM records WHERE account IS NOT NULL UNION SELECT account FROM traffic UNION SELECT account FROM returns",
    );
    for (const { account } of accounts.iterate()) {
      const dCount = db
        .prepare(
          "SELECT count(*) n FROM records WHERE kind='desktop' AND account=?",
        )
        .get(account).n;
      const tCount = db
        .prepare("SELECT count(*) n FROM traffic WHERE account=?")
        .get(account).n;
      const rCount = db
        .prepare("SELECT count(*) n FROM returns WHERE account=?")
        .get(account).n;
      if (dCount) result.accounts.with_desktop++;
      if (tCount || rCount) result.accounts.with_relay_counters++;
      if (dCount && (tCount || rCount)) result.accounts.with_both++;
      if (dCount + tCount + rCount > 500000) {
        result.accounts.too_large_to_analyze++;
        continue;
      }
      const desktops = db
        .prepare(
          "SELECT body FROM records WHERE kind='desktop' AND account=? ORDER BY t",
        )
        .all(account)
        .map((x) => JSON.parse(x.body));
      const counters = db
        .prepare("SELECT body FROM traffic WHERE account=? ORDER BY t")
        .all(account)
        .map((x) => JSON.parse(x.body));
      const traffic = trafficIntervals(counters);
      const successfulReturns = trafficIntervals(
        db
          .prepare("SELECT body FROM returns WHERE account=? ORDER BY t")
          .all(account)
          .map((x) => JSON.parse(x.body)),
      );
      const returnObservation = evaluate(
        desktopIntervals(desktops),
        successfulReturns,
        [],
      );
      result.successful_return_ipv4_bytes.known_counter_deltas +=
        successfulReturns.knownBytes;
      result.successful_return_ipv4_bytes.unaligned +=
        successfulReturns.unalignedBytes;
      result.successful_return_ipv4_bytes.during_multiple_observed_players +=
        returnObservation.offered_bytes_multi;
      const bounds = counters.length
        ? [[counters[0].unix_ms, counters.at(-1).unix_ms]]
        : [];
      const observation = evaluate(
        desktopIntervals(desktops),
        traffic,
        intersect(coverage, bounds),
        { burstBytes },
      );
      const max = desktops.reduce(
        (maximum, d) => (d.valid ? Math.max(maximum, d.players) : maximum),
        0,
      );
      if (max >= 2) result.accounts.with_multiple_observed_players++;
      if (max > 0) result.accounts.with_any_observed_player++;
      if (observation.over_grace_ms > 0)
        result.accounts.over_90s_modelled_multiple_players++;
      result.max_observed_players = Math.max(result.max_observed_players, max);
      result.max_modelled_players_across_devices = Math.max(
        result.max_modelled_players_across_devices,
        observation.max_players,
      );
      if (observation.max_players >= 2)
        result.accounts.with_modelled_multiple_players_across_devices++;
      for (const [key, source] of [
        ["observed_account_seconds", "observed_ms"],
        ["multiple_player_account_seconds", "multi_ms"],
        ["over_90s_account_seconds", "over_grace_ms"],
        [
          "over_90s_with_studio_present_account_seconds",
          "over_grace_with_studio_ms",
        ],
        ["duplicate_device_seconds", "duplicate_device_ms"],
        ["rate_model_covered_account_seconds", "rate_model_covered_ms"],
        ["rate_model_excluded_account_seconds", "rate_model_excluded_ms"],
      ])
        result[key] += observation[source] / 1000;
      result.counter_baselines += traffic.baselines;
      result.offered_inner_bytes.known_counter_deltas += traffic.knownBytes;
      result.offered_inner_bytes.unaligned += traffic.unalignedBytes;
      result.offered_inner_bytes.during_single_observed_player +=
        observation.offered_bytes_single;
      result.offered_inner_bytes.during_multiple_observed_players +=
        observation.offered_bytes_multi;
      result.offered_inner_bytes.during_zero_observed_players +=
        observation.offered_bytes_zero_players;
      result.offered_inner_bytes.without_desktop_observation +=
        observation.offered_bytes_without_desktop;
      for (let i = 0; i < result.rate_models.length; i++) {
        const target = result.rate_models[i],
          source = observation.rate_models[i];
        if (source.modelled_excess_bytes > 0)
          target.accounts_with_modelled_excess++;
        if (source.windows_over_rate > 0)
          target.accounts_with_60s_window_over_rate++;
        target.modelled_excess_bytes += source.modelled_excess_bytes;
        target.complete_60s_windows += source.complete_60s_windows;
        target.windows_over_rate += source.windows_over_rate;
      }
    }
    overhead.sort((a, b) => a - b);
    result.observer_overhead = {
      samples: overhead.length,
      sample_wall_p50_ms:
        overhead[Math.ceil(overhead.length * 0.5) - 1] ?? null,
      sample_wall_p95_ms:
        overhead[Math.ceil(overhead.length * 0.95) - 1] ?? null,
      sample_wall_max_ms: overhead.at(-1) ?? null,
      completed_runs: summaries,
      total_cpu_ms: cpuMs,
      total_wall_ms: wallMs,
      mean_one_core_cpu_percent: wallMs ? (cpuMs / wallMs) * 100 : null,
      includes_startup_compilation: false,
    };
    if (pricePerGb !== null)
      result.cost.modelled_usd_during_multi_player_observation =
        (result.offered_inner_bytes.during_multiple_observed_players / 1e9) *
        pricePerGb;
    if (pricePerGb !== null)
      result.cost.modelled_usd_for_successful_return_leg_during_multi_player_observation =
        (result.successful_return_ipv4_bytes.during_multiple_observed_players /
          1e9) *
        pricePerGb;
    result.rate_model_burst_bytes = burstBytes;
    result.multi_instance_share_of_instrumented_player_accounts = result
      .accounts.with_any_observed_player
      ? result.accounts.with_multiple_observed_players /
        result.accounts.with_any_observed_player
      : null;
    fs.writeFileSync(
      path.join(outDir, "summary.json"),
      JSON.stringify(result, null, 2),
      { flag: "wx" },
    );
    return result;
  } finally {
    db.close();
  }
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.resolve(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1"))
) {
  const args = process.argv.slice(2),
    out = args.shift(),
    priceIndex = args.indexOf("--price-per-gb");
  let pricePerGb = null;
  if (priceIndex !== -1) {
    pricePerGb = Number(args[priceIndex + 1]);
    args.splice(priceIndex, 2);
  }
  if (!out || !args.length)
    throw Error(
      "Usage: analyze.mjs NEW_OUTPUT_DIR INPUT_JSONL... [--price-per-gb EXPLICIT_RATE]",
    );
  const summary = await analyze(args, out, { pricePerGb });
  console.log(
    JSON.stringify(
      {
        accounts: summary.accounts,
        overhead: summary.observer_overhead,
        report: path.join(out, "summary.json"),
      },
      null,
      2,
    ),
  );
}
