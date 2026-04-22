import { describe, expect, it } from "vitest";
import { isDriverMissing, resolveConnectStatus, stateLabel } from "./connectState";

describe("connect state helpers", () => {
  it("formats known VPN states for the connect status line", () => {
    expect(stateLabel("fetching_config")).toBe("Resolving relay\u2026");
    expect(stateLabel("connected")).toBe("Connected");
  });

  it("detects driver-missing errors from backend text", () => {
    expect(
      isDriverMissing(
        "Split tunnel driver not available - please install Windows Packet Filter driver",
      ),
    ).toBe(true);
  });

  it("detects the mid-session recovery error text", () => {
    // connection.rs emits this string when the reader exhausts its rebind budget
    // (workers_panicked → Connected→Error). The UI relies on isDriverMissing()
    // returning true here so the install-driver CTA renders.
    expect(
      isDriverMissing(
        "Split tunnel driver not available — the Windows Packet Filter driver lost its adapter handle and could not recover. Please reconnect, or reinstall the driver.",
      ),
    ).toBe(true);
  });

  it("prioritizes driver install status over generic VPN state", () => {
    expect(
      resolveConnectStatus({
        driverSetupState: "installing",
        driverSetupError: null,
        vpnError: null,
        vpnState: "fetching_config",
      }),
    ).toEqual({
      kind: "text",
      text: "Installing required split tunnel driver\u2026",
    });
  });
});
