import { describe, expect, it, vi } from "vitest";
import { executeGameLaunch } from "./gameLaunchFlow";
import type { GameLaunchPlan } from "./types";
const plan: GameLaunchPlan = { job_id: null, datacenter: null, availability: "unknown", needs_close: true, relay_region: "mumbai", preferences: { datacenter_id: null, fps_cap: 240, graphics_quality: null, use_tunnel: true } };
describe("game launch connection", () => {
  it("waits for the requested connection before launching", async () => {
    let ready!: () => void;
    const connection = new Promise<void>(resolve => { ready = resolve; });
    const launch = vi.fn().mockResolvedValue(undefined);
    const connect = vi.fn(() => connection);
    const pending = executeGameLaunch(plan, { connect, launch });
    expect(connect).toHaveBeenCalledWith("mumbai");
    expect(launch).not.toHaveBeenCalled();
    ready(); await pending;
    expect(launch).toHaveBeenCalledTimes(1);
  });
  it("leaves the prepared connection on when launching fails", async () => {
    let connected = false;
    await expect(executeGameLaunch(plan, {
      connect: async () => { connected = true; },
      launch: async () => { throw new Error("Launcher unavailable"); },
    })).rejects.toThrow("Launcher unavailable");
    expect(connected).toBe(true);
  });
  it("does not start Roblox when connecting fails", async () => {
    const launch = vi.fn();
    await expect(executeGameLaunch(plan, {
      connect: async () => { throw new Error("Relay unavailable"); }, launch,
    })).rejects.toThrow("Relay unavailable");
    expect(launch).not.toHaveBeenCalled();
  });
  it("does not connect when automatic connection is off", async () => {
    const connect = vi.fn(); const launch = vi.fn();
    await executeGameLaunch({ ...plan, preferences: { ...plan.preferences, use_tunnel: false } }, { connect, launch });
    expect(connect).not.toHaveBeenCalled();
    expect(launch).toHaveBeenCalledWith();
  });
});
