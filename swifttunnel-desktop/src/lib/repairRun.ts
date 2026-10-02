import {
  parseSavedRepairResult,
  statusLabel,
  type RepairIssueId,
  type RepairReport,
  type RepairStatus,
} from "./repairCenter";
import { repairCompletion } from "./repairCompletion";

export type RepairItemResult = RepairReport & { id: RepairIssueId; label: string };
export interface RepairRun {
  overall: RepairStatus;
  ranAt: number;
  items: RepairItemResult[];
  interrupted?: string;
}

export function parseRepairRun(raw: string | null): RepairRun | null {
  if (!raw) return null;
  try {
    const run = JSON.parse(raw);
    if (!run || !Number.isFinite(run.ranAt) || !Array.isArray(run.items)) return null;
    const items: RepairItemResult[] = [];
    for (const item of run.items) {
      if (!item || typeof item.label !== "string") return null;
      // Older repair-all results saved only status, summary and changed.
      const parsed = parseSavedRepairResult(JSON.stringify({
        issue: item.id,
        report: {
          nextStep: "", entries: [], reversible: false, ranAt: run.ranAt,
          ...item,
        },
      }));
      if (!parsed) return null;
      items.push({ ...parsed.report, id: parsed.issue, label: item.label });
    }
    const interrupted = typeof run.interrupted === "string" ? run.interrupted.slice(0, 4096) : undefined;
    return { items, ranAt: run.ranAt, overall: interrupted ? "partial" : repairCompletion(items).status, ...(interrupted ? { interrupted } : {}) };
  } catch {
    return null;
  }
}

export function summarizeRepairRun(run: RepairRun): string {
  const labels: [RepairStatus, string][] = [
    ["fixed", "fixed"], ["healthy", "healthy"], ["checked", "checked"],
    ["partial", "partial"], ["needs_reboot", "need reboot"], ["failed", "failed"],
    ["unsupported", "unsupported"], ["not_checked", "not checked"],
  ];
  const parts = labels.flatMap(([status, label]) => {
    const count = run.items.filter((item) => item.status === status).length;
    return count ? [`${count} ${label}`] : [];
  });
  return `${run.interrupted ? `Stopped before completing: ${run.interrupted} ` : ""}Ran ${run.items.length} checks and repairs${parts.length ? `, ${parts.join(", ")}` : ""}.`;
}

export function formatRunForSupport(run: RepairRun): string {
  return [
    "SwiftTunnel Repair (all)",
    `Overall: ${statusLabel(run.overall)}`,
    `Last run: ${new Date(run.ranAt).toLocaleString()}`,
    ...(run.interrupted ? [`Stopped: ${run.interrupted}`] : []),
    "",
    ...run.items.flatMap((item) => [
      `- ${item.label}: ${statusLabel(item.status)}, ${item.summary}`,
      ...(item.nextStep ? [`  Next step: ${item.nextStep}`] : []),
      ...item.entries.map((entry) => `  ${entry.label}: ${entry.value}`),
    ]),
  ].join("\n");
}
