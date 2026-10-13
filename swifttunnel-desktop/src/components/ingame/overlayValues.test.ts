import { describe, expect, it } from "vitest";
import { overlayValues } from "./overlayValues";
import { supportedOverlayMetrics } from "./overlayMetrics";
const game = {
  fps: 120,
  cpuUsage: 12,
  ramUsage: 1536,
  ramTotal: 16384,
  robloxRunning: true,
};
describe("overlay readings", () => {
  it("shows Roblox memory rather than its percentage of total system memory, with distinct latency labels", () => {
    const v = overlayValues(
      game,
      125000,
      { uploadBps: 1024, downloadBps: null },
      10,
      26,
    );
    expect(v.ram).toBe("1.5 GB");
    expect(v.ping).toBe("10 ms");
    expect(v.game_ping).toBe("~26 ms");
    expect(v.playtime).toBe("02:05");
    expect(v.download).toBe("--");
  });
  it("shows unavailable readings without inventing measurements", () => {
    const v = overlayValues(
      { ...game, robloxRunning: false },
      1000,
      { uploadBps: NaN, downloadBps: -1 },
      null,
      NaN,
    );
    for (const id of [
      "fps",
      "cpu",
      "ram",
      "ping",
      "game_ping",
      "upload",
      "download",
    ] as const)
      expect(v[id]).toBe("--");
  });
  it("drops unimplemented sensors and duplicate stats from legacy selections", () => {
    expect(
      supportedOverlayMetrics([
        "fps",
        "gpu",
        "cpu_temp",
        "fps",
        "game_ping",
        "disk",
      ]),
    ).toEqual(["fps", "game_ping"]);
  });
});
