import { describe, expect, it } from "vitest";
import {
  isAdminPrivilegeError,
  shouldResetElevationState,
} from "./adminErrors";

describe("lib/adminErrors", () => {
  it("detects administrator requirement messages", () => {
    expect(
      isAdminPrivilegeError(
        "Administrator privileges required. Please run SwiftTunnel as Administrator.",
      ),
    ).toBe(true);
    expect(
      isAdminPrivilegeError("Please run as administrator to continue."),
    ).toBe(true);
  });

  it("ignores unrelated split tunnel errors", () => {
    expect(
      isAdminPrivilegeError("Split tunnel driver not available on this machine."),
    ).toBe(false);
    expect(isAdminPrivilegeError(null)).toBe(false);
  });

  it("resets elevation state only when vpn error changes", () => {
    expect(
      shouldResetElevationState(
        "Administrator privileges required.",
        "Administrator privileges required.",
      ),
    ).toBe(false);

    expect(
      shouldResetElevationState(
        "Administrator privileges required.",
        "Split tunnel driver not available.",
      ),
    ).toBe(true);

    expect(shouldResetElevationState(null, "Some error")).toBe(true);
    expect(shouldResetElevationState("Some error", null)).toBe(true);
    expect(shouldResetElevationState(null, null)).toBe(false);
  });
});
