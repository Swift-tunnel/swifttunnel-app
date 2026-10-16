import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { useVpnStore } from "./vpnStore";
import { useBoostStore } from "./boostStore";
import { averagePing, jitter, trackTunnelSessions, useSessionStatsStore } from "./sessionStatsStore";

const initialVpn = useVpnStore.getState();
const initialBoost = useBoostStore.getState();
const initialStats = useSessionStatsStore.getState();
let stop: (() => void) | undefined;
beforeEach(() => {
  useVpnStore.setState({ state: "disconnected", connectedAt: null, ping: null, pingReadings: 0 });
  useBoostStore.setState({ robloxRunning: false });
  useSessionStatsStore.setState({ current: null, last: null });
});
afterEach(() => {
  stop?.(); stop = undefined;
  useVpnStore.setState(initialVpn, true);
  useBoostStore.setState(initialBoost, true);
  useSessionStatsStore.setState(initialStats, true);
});

function connect() {
  useVpnStore.setState({ state: "connected", region: "mumbai-05", connectedAt: 1000 });
}
function reading(ping: number) {
  useVpnStore.setState(s => ({ ping, pingReadings: s.pingReadings + 1 }));
}

describe("game-time session ping statistics", () => {
  it("ignores idle relay readings before Roblox starts", () => {
    stop = trackTunnelSessions();
    connect(); reading(1); reading(2);
    const stats = useSessionStatsStore.getState().current!;
    expect(stats.samples).toBe(0);
    expect(stats.lowest).toBeNull();
    expect(averagePing(stats)).toBeNull();
    expect(jitter(stats)).toBeNull();
    expect(useVpnStore.getState().ping).toBe(2);
    expect(useVpnStore.getState().state).toBe("connected");
  });

  it("starts with fresh readings when Roblox opens, even without server metadata", () => {
    stop = trackTunnelSessions();
    connect(); reading(1);
    useBoostStore.setState({ robloxRunning: true });
    expect(useSessionStatsStore.getState().current?.samples).toBe(0);
    reading(20); reading(24);
    const stats = useSessionStatsStore.getState().current!;
    expect(stats.samples).toBe(2);
    expect(stats.lowest).toBe(20);
    expect(averagePing(stats)).toBe(22);
    expect(jitter(stats)).toBe(4);
  });

  it("freezes collected results after Roblox closes and keeps the tunnel connected", () => {
    stop = trackTunnelSessions();
    connect();
    useBoostStore.setState({ robloxRunning: true });
    reading(20); reading(22);
    useBoostStore.setState({ robloxRunning: false });
    const paused = useSessionStatsStore.getState().current;
    reading(1); reading(100);
    expect(useSessionStatsStore.getState().current).toBe(paused);
    expect(paused?.samples).toBe(2);
    expect(paused?.lowest).toBe(20);
    expect(useVpnStore.getState().state).toBe("connected");
  });

  it("resumes without counting a gap as jitter or diluting later jitter", () => {
    stop = trackTunnelSessions();
    connect();
    useBoostStore.setState({ robloxRunning: true });
    reading(20); reading(24);
    useBoostStore.setState({ robloxRunning: false });
    reading(1000);
    useBoostStore.setState({ robloxRunning: true });
    reading(100); reading(102);
    const stats = useSessionStatsStore.getState().current!;
    expect(stats.samples).toBe(4);
    expect(stats.jitterSamples).toBe(2);
    expect(jitter(stats)).toBe(3);
    expect(averagePing(stats)).toBe(62);
  });

  it("retains game-time results on disconnect and starts a clean new session", () => {
    stop = trackTunnelSessions();
    connect();
    useBoostStore.setState({ robloxRunning: true });
    reading(20);
    useBoostStore.setState({ robloxRunning: false }); reading(1);
    useVpnStore.setState({ state: "disconnected", connectedAt: null });
    expect(useSessionStatsStore.getState().current).toBeNull();
    expect(useSessionStatsStore.getState().last?.samples).toBe(1);
    expect(useSessionStatsStore.getState().last?.lowest).toBe(20);
    useVpnStore.setState({ state: "connected", region: "singapore-05", connectedAt: 2000 });
    reading(2);
    expect(useSessionStatsStore.getState().current?.samples).toBe(0);
    expect(useSessionStatsStore.getState().current?.region).toBe("singapore-05");
  });

  it("attaches to an existing connection without replaying its held ping", () => {
    connect(); reading(5);
    useBoostStore.setState({ robloxRunning: true });
    stop = trackTunnelSessions();
    expect(useSessionStatsStore.getState().current?.samples).toBe(0);
    reading(20);
    expect(useSessionStatsStore.getState().current?.samples).toBe(1);
  });

  it("removes both subscriptions when tracking stops", () => {
    stop = trackTunnelSessions();
    connect();
    useBoostStore.setState({ robloxRunning: true }); reading(20);
    stop(); stop = undefined;
    const held = useSessionStatsStore.getState().current;
    useBoostStore.setState({ robloxRunning: false }); reading(50);
    expect(useSessionStatsStore.getState().current).toBe(held);
  });
});
