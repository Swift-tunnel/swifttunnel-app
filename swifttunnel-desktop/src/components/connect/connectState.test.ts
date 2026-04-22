import { describe, expect, it } from "vitest";
import {
  isDriverMissing,
  isDriverVersionTooOld,
  isRebootRequired,
  resolveConnectStatus,
  stateLabel,
} from "./connectState";

describe("connect state helpers", () => {
  it("formats known VPN states for the connect status line", () => {
    expect(stateLabel("fetching_config")).toBe("Resolving relay…");
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
    // (workers_panicked -> Connected->Error). The UI relies on isDriverMissing()
    // returning true here so the install-driver CTA renders.
    expect(
      isDriverMissing(
        "Split tunnel driver not available — the Windows Packet Filter driver lost its adapter handle and could not recover. Please reconnect, or reinstall the driver.",
      ),
    ).toBe(true);
  });

  it("detects reboot-required errors from the installer backend", () => {
    // system_install_driver emits this for 1641/3010 exit codes and for the
    // post-install self-test failure path. The UI renders a distinct
    // "Please restart your PC" CTA instead of re-prompting for another
    // install, which would loop forever on these codes.
    expect(
      isRebootRequired(
        "Reboot required to finish driver installation. Windows signaled exit 3010 and the post-install self-test failed.",
        null,
      ),
    ).toBe(true);
    expect(
      isRebootRequired(null, "reboot required to finish driver installation."),
    ).toBe(true);
    expect(isRebootRequired(null, null)).toBe(false);
    expect(isRebootRequired("Some other failure", null)).toBe(false);
  });

  it("detects older-driver self-test failures", () => {
    // The post-install self-test returns this when a pre-3.6.2 WinpkFilter
    // install (commonly from another VPN product) is detected. UI should
    // offer a driver-service restart rather than a reinstall, which won't
    // help when another product's files are earlier on the service path.
    expect(
      isDriverVersionTooOld(
        "Split tunnel driver is older than SwiftTunnel requires (installed 3.5.1, required >= 3.6.2). Uninstall the other tool's driver, then reinstall SwiftTunnel's driver.",
      ),
    ).toBe(true);
    expect(isDriverVersionTooOld(null)).toBe(false);
    // Auto-install path in vpnStore.ensureDriverReady writes to
    // driverSetupError and only mirrors to vpnError via the outer
    // connect() catch. Checking the second field keeps the match robust
    // if that mirroring ever changes.
    expect(
      isDriverVersionTooOld(
        null,
        "Split tunnel driver is older than SwiftTunnel requires (installed 3.5.1, required >= 3.6.2).",
      ),
    ).toBe(true);
    expect(isDriverVersionTooOld(null, null)).toBe(false);
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
      text: "Installing required split tunnel driver…",
    });
  });

  it("returns reboot_required before falling back to driver_missing", () => {
    // Reboot-required must outrank driver-missing: if the install already
    // told us the system needs a restart, re-prompting for another install
    // is the 1.25.2 "install button does nothing" loop we're trying to end.
    const result = resolveConnectStatus({
      driverSetupState: "idle",
      driverSetupError: null,
      vpnError:
        "Reboot required to finish driver installation. Windows signaled exit 3010.",
      vpnState: "error",
    });
    expect(result.kind).toBe("reboot_required");
  });

  it("returns driver_outdated for pre-3.6.2 driver errors", () => {
    const result = resolveConnectStatus({
      driverSetupState: "idle",
      driverSetupError: null,
      vpnError:
        "Split tunnel driver is older than SwiftTunnel requires (installed 3.5.1, required >= 3.6.2).",
      vpnState: "error",
    });
    expect(result.kind).toBe("driver_outdated");
  });

  it("stops offering the reset button after an attempted reset fails", () => {
    // Guards against the 1.25.2 UX loop: user clicks a "fix it" button,
    // backend says "done", user tries again, same error. The second time
    // around the UI should show the backend's remediation text in full
    // (which already names the concrete action: uninstall the other
    // product's WinpkFilter, reinstall SwiftTunnel) rather than the same
    // button that just didn't help.
    const result = resolveConnectStatus({
      driverSetupState: "error",
      driverSetupError:
        "Split tunnel driver is older than SwiftTunnel requires (installed 3.5.1, required >= 3.6.2). Uninstall the other tool's driver, then reinstall SwiftTunnel's driver.",
      vpnError:
        "Split tunnel driver is older than SwiftTunnel requires (installed 3.5.1, required >= 3.6.2).",
      vpnState: "error",
      driverResetAttempted: true,
    });
    expect(result.kind).toBe("text");
    // The plain-text fallback must include the concrete next step so the
    // user isn't stuck guessing. Checking for the keyword rather than the
    // exact phrasing keeps the test resilient to message tweaks.
    expect(result.text.toLowerCase()).toContain("uninstall");
  });
});
