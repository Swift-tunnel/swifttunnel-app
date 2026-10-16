import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { prepareGameConnection } from "./gameConnection";
import { executeGameLaunch } from "./gameLaunchFlow";
import { useVpnStore } from "../stores/vpnStore";
import { useSettingsStore } from "../stores/settingsStore";
import { useServerStore } from "../stores/serverStore";
import type { GameLaunchPlan } from "./types";

const initialVpn = useVpnStore.getState();
const initialSettings = useSettingsStore.getState();
const initialServers = useServerStore.getState();
const mumbai: GameLaunchPlan = {
  place_id: "10449761463", job_id: "550e8400-e29b-41d4-a716-446655440000",
  datacenter: { id: 7, city: "Mumbai", country: "IN", datacenter_ids: [26120], relay_region: "mumbai" },
  preferences: { datacenter_id: 7, fps_cap: null, graphics_quality: null, use_tunnel: true },
  availability: "available", needs_close: true, relay_region: "mumbai",
};

beforeEach(() => {
  useServerStore.setState({ regions: [
    { id: "mumbai", name: "Mumbai", country_code: "IN", description: "", servers: ["mumbai-01"] },
    { id: "singapore", name: "Singapore", country_code: "SG", description: "", servers: ["singapore-05"] },
  ] });
  useSettingsStore.setState({ settings: { ...initialSettings.settings, selected_region: "singapore", selected_game_presets: [] } });
  useVpnStore.setState({
    state: "connected", region: "singapore-05", error: null,
    fetchState: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn(async () => { useVpnStore.setState({ state: "disconnected", region: null }); }),
    connect: vi.fn(async () => { useVpnStore.setState({ state: "connected", region: "mumbai-01", error: null }); }),
  });
});
afterEach(() => {
  useVpnStore.setState(initialVpn, true);
  useSettingsStore.setState(initialSettings, true);
  useServerStore.setState(initialServers, true);
});

describe("preferred game relay", () => {
  it("waits for Singapore to disconnect and Mumbai to connect before launching", async () => {
    const sequence: string[] = [];
    let ready!: () => void;
    const connected = new Promise<void>(resolve => { ready = resolve; });
    const disconnect = vi.fn(async () => {
      sequence.push("disconnect Singapore");
      useVpnStore.setState({ state: "disconnected", region: null });
    });
    const connect = vi.fn(async () => {
      sequence.push("connect Mumbai");
      await connected;
      useVpnStore.setState({ state: "connected", region: "mumbai-01" });
    });
    useVpnStore.setState({ disconnect, connect });
    const launch = vi.fn(async () => { sequence.push("launch Roblox"); });
    const pending = executeGameLaunch(mumbai, {
      connect: requested => prepareGameConnection(requested, () => {}), launch,
    });
    await vi.waitFor(() => expect(connect).toHaveBeenCalled());
    expect(disconnect).toHaveBeenCalledTimes(1);
    expect(connect).toHaveBeenCalledWith("mumbai", ["roblox"], true);
    expect(launch).not.toHaveBeenCalled();
    ready();
    await pending;
    expect(sequence).toEqual(["disconnect Singapore", "connect Mumbai", "launch Roblox"]);
  });

  it("checks the native session rather than reusing a stale Mumbai UI snapshot", async () => {
    const fetchState = vi.fn(async () => { useVpnStore.setState({ region: "singapore-05" }); });
    useVpnStore.setState({ region: "mumbai-01", fetchState });
    await prepareGameConnection("mumbai", () => {});
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().disconnect).toHaveBeenCalledTimes(1);
    expect(useVpnStore.getState().connect).toHaveBeenCalledWith("mumbai", ["roblox"], true);
  });

  it("reuses an actual Mumbai connection without reconnecting", async () => {
    useVpnStore.setState({ region: "mumbai-01" });
    const preparing = vi.fn();
    await prepareGameConnection("mumbai", preparing);
    expect(preparing).not.toHaveBeenCalled();
    expect(useVpnStore.getState().disconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().connect).not.toHaveBeenCalled();
  });

  it("allows a previous failed session to reconnect to the requested location", async () => {
    useVpnStore.setState({ state: "error", region: null, error: "Previous session failed" });
    await prepareGameConnection("mumbai", () => {});
    expect(useVpnStore.getState().disconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().connect).toHaveBeenCalledWith("mumbai", ["roblox"], true);
  });

  it("does not launch if connecting returns the wrong relay", async () => {
    useVpnStore.setState({ connect: vi.fn(async () => {
      useVpnStore.setState({ state: "connected", region: "singapore-05" });
    }) });
    const launch = vi.fn();
    await expect(executeGameLaunch(mumbai, {
      connect: requested => prepareGameConnection(requested, () => {}), launch,
    })).rejects.toThrow("Couldn't connect to the relay for this location");
    expect(launch).not.toHaveBeenCalled();
  });

  it("does not reuse a session when its native state could not be checked", async () => {
    useVpnStore.setState({ fetchState: vi.fn(async () => { useVpnStore.setState({ error: "Could not read connection" }); }) });
    await expect(prepareGameConnection("mumbai", () => {})).rejects.toThrow("Could not read connection");
    expect(useVpnStore.getState().disconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().connect).not.toHaveBeenCalled();
  });

  it("keeps the current relay when Roblox is explicitly allowed to choose any location", async () => {
    await prepareGameConnection(null, () => {});
    expect(useVpnStore.getState().disconnect).not.toHaveBeenCalled();
    expect(useVpnStore.getState().connect).not.toHaveBeenCalled();
  });
});
