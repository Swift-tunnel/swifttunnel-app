import { expect, it } from "vitest";
import { relayGameEstimate, regionGameEstimate } from "./gamePing";
import type { GameRouteStatus, ServerInfo } from "./types";
import type { ReferenceEstimate } from "./types";

const servers = [
  { region: "mumbai-01", ip: "1.2.3.4", relay_port: 51821, relay_available: true },
  { region: "mumbai-04", ip: "1.2.3.5", relay_port: 51821, relay_available: true },
] as ServerInfo[];
const route: GameRouteStatus = {
  game_location: "Mumbai", relay: "mumbai-04", estimated_path_ms: 26, bypassed: false,
  relay_estimates: [
    { relay: "mumbai-01", address: "1.2.3.4:51821", relay_ms: 20, second_leg_ms: 2, estimated_game_ms: 22 },
    { relay: "mumbai-04", address: "1.2.3.5:51821", relay_ms: 8, second_leg_ms: 18, estimated_game_ms: 26 },
  ],
};
it("compares the whole measured route instead of the nearest relay", () => {
  expect(regionGameEstimate(route, ["mumbai-01", "mumbai-04"], servers)).toBe(22);
  expect(relayGameEstimate(route, servers[1])?.estimated_game_ms).toBe(26);
});
it("does not reuse estimates for changed endpoints, missing paths or bypassed routes", () => {
  expect(relayGameEstimate(route, { ...servers[0], ip: "1.2.3.6" })).toBeUndefined();
  expect(relayGameEstimate({ ...route, bypassed: true }, servers[0])).toBeUndefined();
  expect(regionGameEstimate(null, ["mumbai-01"], servers)).toBeNull();
  expect(regionGameEstimate(route, ["singapore-01"], servers)).toBeNull();
});

const preview = (): ReferenceEstimate => ({ ...route.relay_estimates![0], location: "Mumbai",
  target: "128.116.47.3", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 });
it("shows a reference estimate with no connection or game session", () => {
  expect(relayGameEstimate(null, servers[0], [preview()])?.estimated_game_ms).toBe(22);
  expect(regionGameEstimate(undefined, ["mumbai-01"], servers, [preview()])).toBe(22);
});
it("never mixes a regional reference into an actual game or bypassed comparison", () => {
  const current = { ...route, relay_estimates: [] };
  expect(relayGameEstimate(current, servers[0], [preview()])).toBeUndefined();
  expect(relayGameEstimate({ ...current, bypassed: true }, servers[0], [preview()])).toBeUndefined();
});
it("discards expired references and those for replaced or unavailable relays", () => {
  expect(relayGameEstimate(null, servers[0], [{ ...preview(), expiresAt: 0 }])).toBeUndefined();
  expect(relayGameEstimate(null, { ...servers[0], ip: "5.6.7.8" }, [preview()])).toBeUndefined();
  expect(relayGameEstimate(null, { ...servers[0], relay_available: false }, [preview()])).toBeUndefined();
});
