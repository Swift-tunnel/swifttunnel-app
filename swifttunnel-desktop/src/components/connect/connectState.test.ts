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
