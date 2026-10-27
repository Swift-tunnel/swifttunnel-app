import { describe, expect, it } from "vitest";
import connectTabSource from "./ConnectTab.tsx?raw";
import { resolveConnectStatus } from "./connectState";

describe("ConnectTab hero button", () => {
  it("does not render startup driver diagnostics as the main connection error", () => {
    const diagnostic = "WinpkFilter netcfg failed with code 547: Error code: 0xe0000223; pnputil failed with code -536870365.";
    const status = resolveConnectStatus({ driverSetupState: "error", driverSetupError: diagnostic,
      driverStatus: { installed: false, version: null, ready: false, status: "missing", message: diagnostic, reboot_required: false, recommended_action: "install" },
      vpnError: diagnostic, vpnState: "error" });
    expect(status.text).toContain("device installation services are unavailable");
    expect(status.text).not.toContain("0xe0000223");
  });
  it("renders the primary connect/disconnect action via the Button component", () => {
    expect(connectTabSource).toContain('"Connect"');
    expect(connectTabSource).toContain('"Disconnect"');
    expect(connectTabSource).toContain('"Disconnecting…"');
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
