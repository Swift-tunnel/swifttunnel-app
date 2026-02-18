export function isAdminPrivilegeError(message: string | null): boolean {
  if (!message) return false;

  const lower = message.toLowerCase();
  return (
    lower.includes("administrator privileges required") ||
    lower.includes("run swifttunnel as administrator") ||
    lower.includes("run as administrator")
  );
}

export function shouldResetElevationState(
  previousVpnError: string | null,
  nextVpnError: string | null,
): boolean {
  return previousVpnError !== nextVpnError;
}
