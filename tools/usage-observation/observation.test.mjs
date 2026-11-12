import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import {
  validateRecord,
  desktopIntervals,
  trafficIntervals,
  relayCoverage,
  evaluate,
} from "./model.mjs";
import { accountToken, init, participant } from "./campaign.mjs";
import { analyze } from "./analyze.mjs";
const campaign = "a".repeat(32),
  account = "b".repeat(64),
  device = "c".repeat(64),
  session = "d".repeat(32),
  run = "e".repeat(32),
  base = 1700000000000;
const desktop = (t, players = 2) => ({
  schema: 1,
  kind: "desktop",
  campaign,
  account,
  device,
  session,
  unix_ms: base + t,
  mono_ms: t,
  interval_ms: 5000,
  valid: true,
  players,
  players_with_udp: players,
  studio: 0,
  helpers: 6,
  studio_descendant_players: 0,
  process_error: 0,
  udp4_error: 0,
  udp6_error: 0,
  sample_wall_ms: 1,
});
const counter = (t, bytes, relay = "one", epoch = 1) => ({
  account,
  relay,
  run_id: run,
  unix_ms: base + t,
  sample_mono_ms: t,
  epoch,
  interval_ms: 5000,
  offered: [t, bytes, 0, 0],
  new_flows: 0,
  budget_dropped_packets: 0,
});
const relay = (t, bytes, id = "one") => ({
  schema: 1,
  kind: "relay",
  campaign,
  relay: id,
  run_id: run,
  unix_ms: base + t,
  interval_ms: 5000,
  valid: true,
  busy_accounts: 0,
  account_count: 1,
  truncated: false,
  collection_ms: 1,
  return_sessions: [],
  busy_return_sessions: 0,
  return_sessions_truncated: false,
  accounts: [
    {
      account,
      epoch: 1,
      sample_mono_ms: t,
      offered: [t, bytes, 0, 0],
      new_flows: 0,
      budget_dropped_packets: 0,
    },
  ],
});

test("counts Player instances rather than helpers and applies handover time without enforcing", () => {
  const rows = Array.from({ length: 25 }, (_, i) => desktop(i * 5000));
  const result = evaluate(
    desktopIntervals(rows),
    { intervals: [], gaps: [] },
    [],
  );
  assert.equal(result.max_players, 2);
  assert.equal(result.multi_ms, 120000);
  assert.equal(result.over_grace_ms, 30000);
  assert.equal(rows[0].helpers, 6);
});
test("missing process samples, PID sampler restarts and clock jumps do not become zero or long multi-instance streaks", () => {
  const rows = [desktop(0), desktop(5000), desktop(25000), desktop(30000)];
  assert.equal(
    evaluate(desktopIntervals(rows), { intervals: [], gaps: [] }, []).multi_ms,
    10000,
  );
  assert.equal(
    desktopIntervals([
      desktop(0),
      { ...desktop(5000), session: "f".repeat(32) },
    ]).length,
    0,
  );
  assert.equal(
    desktopIntervals([desktop(0), { ...desktop(5000), unix_ms: base + 15000 }])
      .length,
    0,
  );
});
test("two collectors of the same device are unknown, not two Roblox clients", () => {
  const a = desktopIntervals([desktop(0, 1), desktop(5000, 1)]);
  const b = desktopIntervals([
    { ...desktop(0, 1), session: "f".repeat(32) },
    { ...desktop(5000, 1), session: "f".repeat(32) },
  ]);
  const result = evaluate([...a, ...b], { intervals: [], gaps: [] }, []);
  assert.equal(result.multi_ms, 0);
  assert.equal(result.duplicate_device_ms, 5000);
});
test("account epochs prevent an eviction with higher new totals from creating fake traffic", () => {
  const result = trafficIntervals([
    counter(0, 100),
    counter(5000, 10000, "one", 2),
    counter(10000, 11000, "one", 2),
  ]);
  assert.equal(result.knownBytes, 1000);
  assert.equal(result.baselines, 2);
  assert.equal(result.gaps.length, 2);
});
test("long relay gaps preserve known totals but exclude temporal attribution", () => {
  const result = trafficIntervals([counter(0, 100), counter(30000, 100100)]);
  assert.equal(result.knownBytes, 100000);
  assert.equal(result.unalignedBytes, 100000);
  assert.equal(result.intervals.length, 0);
});
test("a client cannot multiply a model budget by changing relays", () => {
  const rows = [];
  for (let t = 0; t <= 120000; t += 5000)
    for (const r of ["one", "two"]) rows.push(counter(t, t * 1000, r));
  const result = evaluate([], trafficIntervals(rows), [[base, base + 120000]], {
    burstBytes: 0,
  });
  assert.equal(result.rate_models[0].complete_60s_windows, 2);
  assert.equal(result.rate_models[0].windows_over_rate, 2);
  assert.equal(result.rate_models[0].modelled_excess_bytes, 165000000);
  assert.equal(result.rate_models[2].modelled_excess_bytes, 0);
});
test("burst allowance preserves short bulk traffic, while sustained overuse is reported offline", () => {
  const traffic = {
    intervals: [{ start: base, end: base + 1000, rate: 30000 }],
    gaps: [],
  };
  const result = evaluate([], traffic, [[base, base + 1000]]);
  assert.equal(result.rate_models[0].modelled_excess_bytes, 0);
  assert.equal(result.rate_models[0].complete_60s_windows, 0);
});
test("missing, busy and truncated relays never count as complete fleet coverage", () => {
  const rows = [relay(0, 0), relay(5000, 100), relay(10000, 200)];
  assert.deepEqual(relayCoverage(rows), [[base, base + 10000]]);
  assert.deepEqual(
    relayCoverage([rows[0], { ...rows[1], busy_accounts: 1 }, rows[2]]),
    [],
  );
  assert.deepEqual(
    relayCoverage([rows[0], { ...rows[1], account_count: 2 }, rows[2]]),
    [],
  );
});
test("schema rejects destination data, malformed counts and unsafe numeric totals", () => {
  validateRecord(desktop(0));
  validateRecord(relay(0, 0));
  assert.throws(() =>
    validateRecord({ ...desktop(0), destination: "example.invalid" }),
  );
  const sample = relay(0, 0);
  sample.accounts[0].ip = "128.116.1.1";
  assert.throws(() => validateRecord(sample));
  assert.throws(() => validateRecord(desktop(0, -1)));
  const huge = relay(0, 0);
  huge.accounts[0].offered[1] = 2 ** 54;
  assert.throws(() => validateRecord(huge));
});
test("pseudonyms are campaign-specific and participant files do not contain source account IDs", () => {
  const key = randomBytes(32);
  assert.equal(
    accountToken(key, "account-id"),
    accountToken(key, " account-id "),
  );
  assert.notEqual(
    accountToken(key, "account-id"),
    accountToken(randomBytes(32), "account-id"),
  );
});
test("streaming analyzer deduplicates evidence, reports modeled impact and leaves excess-instance cost unknown", async () => {
  const root = path.join(
    "C:/Users/supre/swift/audit-followup/usage-observation-tests",
    randomBytes(8).toString("hex"),
  );
  fs.mkdirSync(root, { recursive: true });
  init(path.join(root, "campaign"));
  const identity = path.join(root, "identity.local");
  fs.writeFileSync(identity, "private-account-id");
  participant(
    path.join(root, "campaign"),
    identity,
    path.join(root, "participant.json"),
  );
  assert.equal(
    fs
      .readFileSync(path.join(root, "participant.json"), "utf8")
      .includes("private-account-id"),
    false,
  );
  const rows = [
    {
      schema: 1,
      kind: "campaign_relays",
      campaign,
      relays: ["one"],
      interval_ms: 5000,
    },
  ];
  for (let t = 0; t <= 120000; t += 5000) {
    const sample = relay(t, t * 2000);
    sample.return_sessions = [
      {
        account,
        session: "1".repeat(64),
        created_at: 100,
        sample_mono_ms: t,
        frame_bytes_out: t * 1000,
        packets_out: t / 5000,
      },
    ];
    rows.push(desktop(t), sample);
  }
  const input = path.join(root, "input.jsonl");
  fs.writeFileSync(input, rows.map((x) => JSON.stringify(x)).join("\n"));
  const result = await analyze([input, input], path.join(root, "result"), {
    pricePerGb: 0.12,
    burstBytes: 0,
  });
  assert.equal(result.accounts.with_multiple_observed_players, 1);
  assert.equal(result.accounts.over_90s_modelled_multiple_players, 1);
  assert.equal(result.over_90s_account_seconds, 30);
  assert.equal(
    result.offered_inner_bytes.during_multiple_observed_players,
    240000000,
  );
  assert.equal(result.rate_models[0].modelled_excess_bytes, 165000000);
  assert.equal(
    result.cost.modelled_usd_during_multi_player_observation,
    0.0288,
  );
  assert.equal(result.cost.extra_instances_cost, null);
  assert.equal(
    result.successful_return_ipv4_bytes.known_counter_deltas,
    120000672,
  );
  assert.equal(
    result.successful_return_ipv4_bytes.during_multiple_observed_players,
    120000672,
  );
  assert.ok(
    Math.abs(
      result.cost
        .modelled_usd_for_successful_return_leg_during_multi_player_observation -
        0.01440008064,
    ) < 1e-12,
  );
  assert.equal(result.inputs.duplicate_records_ignored, 50);
  assert.equal(result.inputs.fleet_complete_ms, 120000);
});
