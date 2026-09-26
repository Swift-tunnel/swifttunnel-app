import type { RepairReport, RepairStatus } from "./repairCenter";

type RepairResult = Pick<RepairReport, "status" | "changed">;

/** Keep incomplete results visible instead of dismissing them with a restart. */
export function repairCompletion(items: readonly RepairResult[]): {
  status: RepairStatus;
  type: "success" | "warning" | "error";
  message: string;
  restart: boolean;
} {
  const has = (status: RepairStatus) => items.some((item) => item.status === status);
  const reboot = has("needs_reboot");
  if (has("failed") || has("partial")) {
    return {
      status: has("failed") ? "failed" : "partial",
      type: has("failed") ? "error" : "warning",
      message: `Some repairs could not complete. Review the results below.${
        reboot ? " Restart Windows to finish the changes that require it." : ""
      }`,
      restart: false,
    };
  }
  if (reboot) {
    return {
      status: "needs_reboot",
      type: "warning",
      message: "Restart Windows to finish the repairs. Restarting SwiftTunnel alone is not enough.",
      restart: false,
    };
  }
  if (!items.length || has("unsupported") || has("not_checked")) {
    return {
      status: "partial",
      type: "warning",
      message: "Some checks could not run. Review the results below before trying again.",
      restart: false,
    };
  }
  const changed = items.some((item) => item.changed);
  return {
    status: has("fixed") ? "fixed" : has("checked") ? "checked" : "healthy",
    type: "success",
    message: changed
      ? "Repairs complete, restarting SwiftTunnel…"
      : "Checks complete, no changes were needed. Review the results below.",
    restart: changed,
  };
}
