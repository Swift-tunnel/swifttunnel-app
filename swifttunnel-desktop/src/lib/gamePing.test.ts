import { expect, it } from "vitest";
import { relayReferenceEstimate, regionGameEstimate } from "./gamePing";
import type { ServerInfo, ReferenceEstimate } from "./types";
const servers = [
  { region: "mumbai-01", ip: "1.2.3.4", relay_port: 51821, relay_available: true },
  { region: "mumbai-04", ip: "1.2.3.5", relay_port: 51821, relay_available: true },
] as ServerInfo[];
const preview = (): ReferenceEstimate => ({ relay: "mumbai-01", address: "1.2.3.4:51821",
  relay_ms: 20, second_leg_ms: 2, estimated_game_ms: 22, location: "Mumbai",
  target: "128.116.47.3", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 });
it("shows the regional estimate before any game or connection exists", () => {
  expect(relayReferenceEstimate(servers[0], [preview()])?.estimated_game_ms).toBe(22);
  expect(regionGameEstimate(["mumbai-01"], servers, [preview()])).toBe(22);
  expect(regionGameEstimate(["missing-region"], servers, [preview()])).toBeNull();
});
it("uses both measured legs to find the best relay within a region", () => {
  const rows = [preview(), { ...preview(), relay: "mumbai-04", address: "1.2.3.5:51821",
    relay_ms: 8, second_leg_ms: 18, estimated_game_ms: 26 }];
  expect(regionGameEstimate(["mumbai-01", "mumbai-04"], servers, rows)).toBe(22);
});
it("discards expired references and those for replaced or unavailable relays", () => {
  expect(relayReferenceEstimate(servers[0], [{ ...preview(), expiresAt: 0 }])).toBeUndefined();
  expect(relayReferenceEstimate({ ...servers[0], ip: "5.6.7.8" }, [preview()])).toBeUndefined();
  expect(relayReferenceEstimate({ ...servers[0], relay_available: false }, [preview()])).toBeUndefined();
});
