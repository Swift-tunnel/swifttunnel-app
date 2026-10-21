// Saved repair data and display labels, independent of repair execution.

import type { StartupRegistrationSnapshot } from "./commands";

export const REPAIR_ISSUE_IDS = [
  "no_internet",
  "driver",
  "adapter",
  "tunnel_cleanup",
  "windows_firewall",
  "route_assist",
  "roblox",
  "network_booster",
  "startup",
  "relay",
  "installer",
  "translations",
  "overlay_layout",
  "roblox_reset",
] as const;
export type RepairIssueId = (typeof REPAIR_ISSUE_IDS)[number];

export type RepairStatus =
  | "not_checked"
  | "healthy"
  | "checked"
  | "fixed"
  | "partial"
  | "needs_reboot"
  | "failed"
  | "unsupported";

const REPAIR_STATUSES: readonly RepairStatus[] = [
  "not_checked",
  "healthy",
  "checked",
  "fixed",
  "partial",
  "needs_reboot",
  "failed",
  "unsupported",
];

export interface RepairIssueDefinition {
  id: RepairIssueId;
  label: string;
  description: string;
  actionLabel: "Check" | "Repair";
  systemChanging: boolean;
}

export interface RepairEntry {
  label: string;
  value: string;
  tone?: "default" | "good" | "warn" | "bad";
  mono?: boolean;
}

export type RepairRollback = {
  kind: "startup_registration";
  snapshot: StartupRegistrationSnapshot;
};

export interface RepairReport {
  status: RepairStatus;
  summary: string;
  nextStep: string;
  changed: boolean;
  reversible: boolean;
  ranAt: number;
  entries: RepairEntry[];
  rollback?: RepairRollback;
}

export type SavedRepairResult = {
  issue: RepairIssueId;
  report: RepairReport;
};

export function parseSavedRepairResult(raw: string | null): SavedRepairResult | null {
  if (!raw) return null;

  try {
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) return null;

    const issue = parsed.issue;
    const report = parsed.report;
    if (!isRepairIssueId(issue) || !isRepairReport(report)) return null;

    return { issue, report };
  } catch {
    return null;
  }
}

function isRepairIssueId(value: unknown): value is RepairIssueId {
  return (
    typeof value === "string" &&
    REPAIR_ISSUE_IDS.includes(value as RepairIssueId)
  );
}

function isRepairReport(value: unknown): value is RepairReport {
  if (!isRecord(value)) return false;
  if (!isRepairStatus(value.status)) return false;
  if (typeof value.summary !== "string") return false;
  if (typeof value.nextStep !== "string") return false;
  if (typeof value.changed !== "boolean") return false;
  if (typeof value.reversible !== "boolean") return false;
  if (typeof value.ranAt !== "number" || !Number.isFinite(value.ranAt)) {
    return false;
  }
  if (!Array.isArray(value.entries) || !value.entries.every(isRepairEntry)) {
    return false;
  }
  if (
    value.rollback !== undefined &&
    !isRepairRollback(value.rollback)
  ) {
    return false;
  }
  return true;
}

function isRepairStatus(value: unknown): value is RepairStatus {
  return (
    typeof value === "string" &&
    REPAIR_STATUSES.includes(value as RepairStatus)
  );
}

function isRepairEntry(value: unknown): value is RepairEntry {
  if (!isRecord(value)) return false;
  if (typeof value.label !== "string") return false;
  if (typeof value.value !== "string") return false;
  if (
    value.tone !== undefined &&
    value.tone !== "default" &&
    value.tone !== "good" &&
    value.tone !== "warn" &&
    value.tone !== "bad"
  ) {
    return false;
  }
  if (value.mono !== undefined && typeof value.mono !== "boolean") {
    return false;
  }
  return true;
}

function isRepairRollback(value: unknown): value is RepairRollback {
  if (!isRecord(value)) return false;
  if (value.kind !== "startup_registration") return false;
  return isStartupRegistrationSnapshot(value.snapshot);
}

function isStartupRegistrationSnapshot(
  value: unknown,
): value is StartupRegistrationSnapshot {
  if (!isRecord(value)) return false;
  return (
    typeof value.exists === "boolean" &&
    (value.value === null || typeof value.value === "string")
  );
}

export function statusLabel(status: RepairStatus): string {
  switch (status) {
    case "not_checked":
      return "Not checked";
    case "healthy":
      return "Healthy";
    case "checked":
      return "Checked";
    case "fixed":
      return "Fixed";
    case "partial":
      return "Partial";
    case "needs_reboot":
      return "Needs reboot";
    case "failed":
      return "Failed";
    case "unsupported":
      return "Unsupported";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
