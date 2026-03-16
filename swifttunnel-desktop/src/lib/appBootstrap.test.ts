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
    const connectVpn = vi.fn().mockResolvedValue(undefined);
    const checkForUpdates = vi.fn().mockResolvedValue(undefined);

    await runAppBootstrap({
      initEventListeners,
      fetchAuth,
      loadSettings,
      fetchServers,
      fetchSystemInfo,
      fetchVpnState,
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
    expect(fetchAuth).toHaveBeenCalledTimes(1);
    expect(loadSettings).toHaveBeenCalledTimes(1);
    expect(fetchServers).toHaveBeenCalledTimes(1);
    expect(fetchSystemInfo).toHaveBeenCalledTimes(1);
    expect(fetchVpnState).toHaveBeenCalledTimes(1);
    expect(connectVpn).toHaveBeenCalledWith("singapore", ["roblox"]);
    expect(checkForUpdates).toHaveBeenCalledWith(false, true);
  });

  it("skips reconnect and update check when startup conditions are not met", async () => {
    const connectVpn = vi.fn().mockResolvedValue(undefined);
    const checkForUpdates = vi.fn().mockResolvedValue(undefined);

    await runAppBootstrap({
      initEventListeners: vi.fn().mockResolvedValue(undefined),
      fetchAuth: vi.fn().mockResolvedValue(undefined),
      loadSettings: vi.fn().mockResolvedValue(undefined),
      fetchServers: vi.fn().mockResolvedValue(undefined),
      fetchSystemInfo: vi.fn().mockResolvedValue(undefined),
      fetchVpnState: vi.fn().mockResolvedValue(undefined),
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
  });
});
