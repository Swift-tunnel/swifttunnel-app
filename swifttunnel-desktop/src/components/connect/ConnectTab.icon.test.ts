import { describe, expect, it } from "vitest";
import connectTabSource from "./ConnectTab.tsx?raw";
import { resolveConnectStatus } from "./connectState";

describe("ConnectTab hero button", () => {
  it("renders the primary connect/disconnect action via the Button component", () => {
    expect(connectTabSource).toContain('"Connect"');
    expect(connectTabSource).toContain('"Disconnect"');
    expect(connectTabSource).toMatch(/<Button[^>]*variant=\{buttonVariant\}/);
  });

  it("shows automatic split tunnel driver install status text", () => {
    expect(
      resolveConnectStatus({
        driverSetupState: "checking",
        driverSetupError: null,
        vpnError: null,
        vpnState: "disconnected",
      }).text,
    ).toContain("Checking split tunnel driver");
    expect(
      resolveConnectStatus({
        driverSetupState: "installing",
        driverSetupError: null,
        vpnError: null,
        vpnState: "disconnected",
      }).text,
    ).toContain("Installing required split tunnel driver");
  });
});
