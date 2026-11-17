import {
  MAX_SAVED_REPAIR_LENGTH,
  REPAIR_ISSUE_IDS,
  parseSavedRepairResult,
  statusLabel,
  type RepairIssueId,
  type RepairReport,
  type RepairStatus,
} from "./repairResults";
import { repairCompletion } from "./repairCompletion";

export type RepairItemResult = RepairReport & { id: RepairIssueId; label: string };
export interface RepairRun {
  overall: RepairStatus;
  ranAt: number;
  items: RepairItemResult[];
  interrupted?: string;
  /** Which problem the run was started for. Absent on older saved runs. */
  scope?: string;
}

/** One plain sentence for the player. The per-check wording stays in details. */
export function plainRunSummary(run: RepairRun): string {
  const count = (...statuses: RepairStatus[]) =>
    run.items.filter((item) => statuses.includes(item.status)).length;
  const things = (n: number) => (n === 1 ? "1 thing" : `${n} things`);
  const capital = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
  const parts: string[] = [];
  const fixed = count("fixed");
  const failed = count("failed", "partial");
  const skipped = count("unsupported", "not_checked");
  if (run.interrupted) parts.push("Repair stopped before it finished.");
  if (fixed) parts.push(`Fixed ${things(fixed)}.`);
  if (failed) parts.push(capital(`${things(failed)} ${failed === 1 ? "needs" : "need"} attention.`));
  if (count("needs_reboot")) parts.push("Restart Windows to finish.");
  if (skipped) parts.push(capital(`${things(skipped)} could not be checked.`));
  if (!parts.length) {
    parts.push(run.items.length
      ? `No problems found in the ${things(run.items.length)} checked.`
      : "Nothing was checked.");
  }
  return parts.join(" ");
}

export function parseRepairRun(raw: string | null): RepairRun | null {
  if (!raw || raw.length > MAX_SAVED_REPAIR_LENGTH) return null;
  try {
    const run = JSON.parse(raw);
    if (!run || !Number.isFinite(run.ranAt) || !Array.isArray(run.items)
      || run.items.length > REPAIR_ISSUE_IDS.length) return null;
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
    const scope = typeof run.scope === "string" && run.scope ? run.scope.slice(0, 80) : undefined;
    return { items, ranAt: run.ranAt, overall: interrupted ? "partial" : repairCompletion(items).status, ...(interrupted ? { interrupted } : {}), ...(scope ? { scope } : {}) };
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
    `SwiftTunnel Repair (${run.scope ?? "all"})`,
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
