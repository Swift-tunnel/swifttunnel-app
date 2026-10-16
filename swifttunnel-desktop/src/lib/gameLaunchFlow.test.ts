import { describe, expect, it, vi } from "vitest";
import { executeGameLaunch, verifyGameLaunchLocation } from "./gameLaunchFlow";
import type { GameLaunchPlan } from "./types";
const plan: GameLaunchPlan = { job_id: null, datacenter: null, availability: "unknown", needs_close: true, relay_region: "mumbai", preferences: { datacenter_id: null, fps_cap: 240, graphics_quality: null, use_tunnel: true } };
describe("game launch connection", () => {
  const center = { id: 7, city: "Mumbai", country: "IN", datacenter_ids: [26120], relay_region: "mumbai" };

  it("rejects a dropped preferred location but preserves explicit fallback and rejoin", () => {
    const dropped = { ...plan, relay_region: null, preferences: { ...plan.preferences, datacenter_id: 7 } };
    expect(() => verifyGameLaunchLocation(dropped, null, null, true)).toThrow("chosen location wasn't applied");
    expect(() => verifyGameLaunchLocation(dropped, null, null, false)).not.toThrow();
    expect(() => verifyGameLaunchLocation(dropped, "saved-job", null, false)).not.toThrow();
    expect(() => verifyGameLaunchLocation({ ...dropped, preferences: { ...dropped.preferences, skip_matchmaker: true } }, null, null, true)).not.toThrow();
    expect(() => verifyGameLaunchLocation({ ...dropped, datacenter: center }, null, null, true)).not.toThrow();
  });

  it("keeps an explicit server location even when a different preference was saved", () => {
    const explicit = { ...plan, datacenter: center, preferences: { ...plan.preferences, datacenter_id: 10 } };
    expect(() => verifyGameLaunchLocation(explicit, "job", 7, false)).not.toThrow();
    expect(() => verifyGameLaunchLocation({ ...explicit, datacenter: null }, "job", 7, false)).toThrow("chosen location wasn't applied");
  });

  it.each([null, "singapore"])("does not connect or launch a Mumbai plan with relay %s", async relay_region => {
    const connect = vi.fn();
    const launch = vi.fn();
    await expect(executeGameLaunch({ ...plan, datacenter: center, relay_region }, { connect, launch }))
      .rejects.toThrow("relay doesn't match the chosen location");
    expect(connect).not.toHaveBeenCalled();
    expect(launch).not.toHaveBeenCalled();
  });

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
  it("does not preapprove an unknown server after connecting from a verified plan", async () => {
    const job = "550e8400-e29b-41d4-a716-446655440000";
    const sequence: string[] = [];
    await expect(executeGameLaunch({ ...plan, job_id: job, availability: "available" }, {
      connect: async () => { sequence.push("connected"); },
      launch: async allowUnverified => {
        sequence.push("checked again");
        if (!allowUnverified) throw new Error("Review the unverified server before joining");
      },
    })).rejects.toThrow("Review the unverified server");
    expect(sequence).toEqual(["connected", "checked again"]);
    const launch = vi.fn().mockResolvedValue(undefined);
    await executeGameLaunch({ ...plan, job_id: job, availability: "unknown" }, { connect: async () => {}, launch });
    expect(launch).toHaveBeenCalledWith(true);
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
    expect(launch).toHaveBeenCalledWith(false);
  });
});
