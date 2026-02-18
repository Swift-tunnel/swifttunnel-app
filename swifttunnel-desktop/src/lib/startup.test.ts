import { describe, expect, it } from "vitest";
import { shouldAutoReconnectOnLaunch } from "./startup";

describe("shouldAutoReconnectOnLaunch", () => {
  it("returns true when auth is logged in, vpn is disconnected, and settings allow reconnect", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
    ).toBe(true);
  });

  it("returns false when user is not logged in", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_out", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: true,
      }),
    ).toBe(false);
  });

  it("returns false when reconnect is disabled or no prior active tunnel marker exists", () => {
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: false,
        resume_vpn_on_startup: true,
      }),
    ).toBe(false);
    expect(
      shouldAutoReconnectOnLaunch("logged_in", "disconnected", {
        auto_reconnect: true,
        resume_vpn_on_startup: false,
      }),
    ).toBe(false);
  });
});
