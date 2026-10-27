import { expect, it } from "vitest";
import { formatDriverSetupMessage } from "./driverMessages";

it.each(["0xe0000223", "0x800F0223", "-536870365", "ERROR_NO_CONFIGMGR_SERVICES", "The Plug and Play service is not available on the remote machine."])(
  "explains Windows device installation failure for %s without exposing the diagnostic dump",
  detail => {
    const message = formatDriverSetupMessage(`WinpkFilter netcfg binding install failed: ${detail}; Installer log: C:\\ProgramData\\SwiftTunnel\\driver-work\\fixture\\install.log`);
    expect(message).toContain("device installation services are unavailable");
    expect(message).toContain("Restart Windows");
    expect(message).toContain("contact support");
    expect(message).not.toContain(detail);
    expect(message).not.toContain("ProgramData");
  },
);
it("keeps unrelated errors intact and gives unknown raw driver output a readable fallback", () => {
  expect(formatDriverSetupMessage("Account error 0xe0000223")).toBe("Account error 0xe0000223");
  expect(formatDriverSetupMessage("Close Roblox first.")).toBe("Close Roblox first.");
  for (const guidance of ["WinpkFilter: administrator privileges required", "WinpkFilter failed to open: access is denied", "Reboot required to finish WinpkFilter installation; Installer log: fixture"]) {
    expect(formatDriverSetupMessage(guidance)).toBe(guidance);
  }
  expect(formatDriverSetupMessage("WinpkFilter pnputil failed: unexpected code 123456")).not.toContain("123456");
});
