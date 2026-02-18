import { describe, expect, it } from "vitest";
import { isAdminPrivilegeError } from "./adminErrors";

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
});
