import { describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS } from "./settings";
import { runAppBootstrap } from "./appBootstrap";

describe("app bootstrap", () => {
  it("loads dependencies, reconnects, and checks updates", async () => {
    const initEventListeners = vi.fn().mockResolvedValue(undefined);
    const fetchAuth = vi.fn().mockResolvedValue(undefined);
    const loadSettings = vi.fn().mockResolvedValue(undefined);
    const fetchServers = vi.fn().mockResolvedValue(undefined);
    const fetchSystemInfo = vi.fn().mockResolvedValue(undefined);
    const fetchVpnState = vi.fn().mockResolvedValue(undefined);
    const refreshAuthProfile = vi.fn().mockResolvedValue(undefined);
    const connectVpn = vi.fn().mockResolvedValue(undefined);
    const checkForUpdates = vi.fn().mockResolvedValue(undefined);

    await runAppBootstrap({
      initEventListeners,
      fetchAuth,
      loadSettings,
      fetchServers,
      fetchSystemInfo,
      fetchVpnState,
      refreshAuthProfile,
      getSettings: () => ({
        ...DEFAULT_SETTINGS,
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
      getAuthState: () => "logged_in",
      getVpnState: () => "disconnected",
      connectVpn,
      checkForUpdates,
    });

    expect(initEventListeners).toHaveBeenCalledTimes(1);
    expect(loadSettings).toHaveBeenCalledTimes(1);
    expect(fetchServers).toHaveBeenCalledTimes(1);
    expect(fetchSystemInfo).toHaveBeenCalledTimes(1);
    expect(fetchAuth).toHaveBeenCalledTimes(2);
    expect(fetchVpnState).toHaveBeenCalledTimes(2);
    expect(refreshAuthProfile).toHaveBeenCalledTimes(1);
    expect(connectVpn).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(checkForUpdates).toHaveBeenCalledWith(false, false);
  });

  it("skips reconnect and update check when startup conditions are not met", async () => {
    const connectVpn = vi.fn().mockResolvedValue(undefined);
    const checkForUpdates = vi.fn().mockResolvedValue(undefined);
    const refreshAuthProfile = vi.fn().mockResolvedValue(undefined);

    await runAppBootstrap({
      initEventListeners: vi.fn().mockResolvedValue(undefined),
      fetchAuth: vi.fn().mockResolvedValue(undefined),
      loadSettings: vi.fn().mockResolvedValue(undefined),
      fetchServers: vi.fn().mockResolvedValue(undefined),
      fetchSystemInfo: vi.fn().mockResolvedValue(undefined),
      fetchVpnState: vi.fn().mockResolvedValue(undefined),
      refreshAuthProfile,
      getSettings: () => ({
        ...DEFAULT_SETTINGS,
        update_settings: { auto_check: false, last_check: null },
      }),
      getAuthState: () => "logged_out",
      getVpnState: () => "connected",
      connectVpn,
      checkForUpdates,
    });

    expect(connectVpn).not.toHaveBeenCalled();
    expect(checkForUpdates).not.toHaveBeenCalled();
    expect(refreshAuthProfile).not.toHaveBeenCalled();
  });

  it("refreshes profile before reconnect so a startup ban can block auto-connect", async () => {
    const connectVpn = vi.fn().mockResolvedValue(undefined);
    let authState: "logged_in" | "banned" = "logged_in";
    let vpnState: "connected" | "disconnected" = "connected";
    let fetchAuthCalls = 0;
    let fetchVpnStateCalls = 0;

    await runAppBootstrap({
      initEventListeners: vi.fn().mockResolvedValue(undefined),
      fetchAuth: vi.fn().mockImplementation(async () => {
        fetchAuthCalls += 1;
        if (fetchAuthCalls > 1) {
          authState = "banned";
        }
      }),
      loadSettings: vi.fn().mockResolvedValue(undefined),
      fetchServers: vi.fn().mockResolvedValue(undefined),
      fetchSystemInfo: vi.fn().mockResolvedValue(undefined),
      fetchVpnState: vi.fn().mockImplementation(async () => {
        fetchVpnStateCalls += 1;
        if (fetchVpnStateCalls > 1) {
          vpnState = "disconnected";
        }
      }),
      refreshAuthProfile: vi.fn().mockResolvedValue(undefined),
      getSettings: () => ({
        ...DEFAULT_SETTINGS,
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
      getAuthState: () => authState,
      getVpnState: () => vpnState,
      connectVpn,
      checkForUpdates: vi.fn().mockResolvedValue(undefined),
    });

    expect(connectVpn).not.toHaveBeenCalled();
  });

  it("does not refresh profile or reconnect once auth is already banned", async () => {
    const fetchAuth = vi.fn().mockResolvedValue(undefined);
    const fetchVpnState = vi.fn().mockResolvedValue(undefined);
    const refreshAuthProfile = vi.fn().mockResolvedValue(undefined);
    const connectVpn = vi.fn().mockResolvedValue(undefined);

    await runAppBootstrap({
      initEventListeners: vi.fn().mockResolvedValue(undefined),
      fetchAuth,
      loadSettings: vi.fn().mockResolvedValue(undefined),
      fetchServers: vi.fn().mockResolvedValue(undefined),
      fetchSystemInfo: vi.fn().mockResolvedValue(undefined),
      fetchVpnState,
      refreshAuthProfile,
      getSettings: () => ({
        ...DEFAULT_SETTINGS,
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
      getAuthState: () => "banned",
      getVpnState: () => "disconnected",
      connectVpn,
      checkForUpdates: vi.fn().mockResolvedValue(undefined),
    });

    expect(fetchAuth).toHaveBeenCalledTimes(1);
    expect(fetchVpnState).toHaveBeenCalledTimes(1);
    expect(refreshAuthProfile).not.toHaveBeenCalled();
    expect(connectVpn).not.toHaveBeenCalled();
  });
});
