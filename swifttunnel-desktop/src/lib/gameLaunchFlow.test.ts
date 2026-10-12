import { describe, expect, it, vi } from "vitest";
import { executeGameLaunch } from "./gameLaunchFlow";
import type { GameLaunchPlan } from "./types";
const plan: GameLaunchPlan = { job_id: null, datacenter: null, availability: "unknown", needs_close: true, relay_region: "mumbai", preferences: { datacenter_id: null, fps_cap: 240, graphics_quality: null, use_tunnel: true } };
describe("game launch ownership", () => {
  it("prepares the connection before launching and cleans up a failed owned launch", async () => {
    const sequence: string[] = [];
    const cleanup = vi.fn(async () => { sequence.push("cleanup"); });
    await expect(executeGameLaunch(plan, { connect: async () => { sequence.push("connect"); return { owned: true, token: 12 }; }, launch: async () => { sequence.push("launch"); throw new Error("Launcher unavailable"); }, cleanup })).rejects.toThrow("Launcher unavailable");
    expect(sequence).toEqual(["connect", "launch", "cleanup"]);
    expect(cleanup).toHaveBeenCalledWith(12);
  });
  it("never disconnects a connection the player already had", async () => {
    const cleanup = vi.fn();
    await expect(executeGameLaunch(plan, { connect: async () => ({ owned: false, token: null }), launch: async () => { throw new Error("Join failed"); }, cleanup })).rejects.toThrow("Join failed");
    expect(cleanup).not.toHaveBeenCalled();
  });
  it("does not connect or consume playtime when automatic connection is off", async () => {
    const connect = vi.fn(); const launch = vi.fn();
    await executeGameLaunch({ ...plan, preferences: { ...plan.preferences, use_tunnel: false } }, { connect, launch, cleanup: vi.fn() });
    expect(connect).not.toHaveBeenCalled(); expect(launch).toHaveBeenCalledWith(false);
  });
  it("reports a cleanup failure instead of claiming that the connection stopped", async () => {
    await expect(executeGameLaunch(plan, { connect: async () => ({ owned: true, token: 12 }), launch: async () => { throw new Error("Join failed"); }, cleanup: async () => { throw new Error("Driver busy"); } })).rejects.toThrow("Open Connect and disconnect it manually");
  });
});
