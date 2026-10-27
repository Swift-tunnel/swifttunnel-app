export function isWindowsDriverInstallerFailureMessage(message: string): boolean {
  const lower = message.toLowerCase();
  return /ndisrd|winpkfilter|windows packet filter|split[- ]tunnel driver/.test(lower) && (
    lower.includes("netcfg failed with code 1753")
    || lower.includes("0x800106d9")
    || lower.includes("msiexec code 1603")
    || lower.includes("there are no more endpoints available from the endpoint mapper")
    || lower.includes("driver file not found, cannot create ndisrd service")
  );
}

/** Main-screen guidance. Raw driver output stays in status details/support logs. */
export function formatDriverSetupMessage(message: string): string {
  const lower = message.toLowerCase();
  const driver = /ndisrd|winpkfilter|windows packet filter|split[- ]tunnel driver/.test(lower);
  if (driver && (
    /0xe0000223\b|0x800f0223\b|\b536870365\b|no_configmgr_services/.test(lower)
    || lower.includes("plug and play service is not available")
  )) {
    return "Windows couldn't install SwiftTunnel's network driver because its device installation services are unavailable. Restart Windows and try Repair once. If it still fails, contact support with your log.";
  }
  if (isWindowsDriverInstallerFailureMessage(message)) {
    return "Windows could not install SwiftTunnel's split-tunnel driver because Windows networking/driver services are not responding cleanly. Open the Repair tab and run \"Reinstall driver\". If that does not fix it, contact support with the log file.";
  }
  // Keep existing permission/reboot guidance intact for the action policy.
  if (/access (?:is )?denied|administrator privileges required|reboot required|marked for deletion/.test(lower)) {
    return message;
  }
  if (driver && /failed to open|netcfg failed|pnputil failed|installer log:/.test(lower)) {
    return "SwiftTunnel couldn't install or start its network driver. Restart Windows, then try Repair. If it still fails, contact support with your log.";
  }
  return message;
}
