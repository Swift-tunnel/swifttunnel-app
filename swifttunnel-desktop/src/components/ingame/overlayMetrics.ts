import type { OverlayMetric } from "../../lib/types";

export interface OverlayMetricMeta {
  id: OverlayMetric;
  label: string;
  group: "Basic" | "CPU" | "GPU" | "RAM" | "Hard Disk";
  /** Not wired to live data yet (needs hardware sensors for temps, etc.). */
  soon?: boolean;
  /** Sample value for the preview. */
  sample: string;
}

/** Legacy sensor IDs remain readable; only metrics with live data are selectable. */
export const OVERLAY_METRICS: OverlayMetricMeta[] = [
  { id: "fps", label: "FPS", group: "Basic", sample: "120" },
  { id: "ping", label: "Relay", group: "Basic", sample: "38 ms" },
  { id: "game_ping", label: "Game ping", group: "Basic", sample: "~26 ms" },
  { id: "time", label: "Time", group: "Basic", sample: "16:48:59" },
  { id: "playtime", label: "Play time", group: "Basic", sample: "00:42" },
  { id: "battery", label: "Battery", group: "Basic", soon: true, sample: "87%" },
  { id: "upload", label: "Upload", group: "Basic", sample: "12 KB/s" },
  { id: "download", label: "Download", group: "Basic", sample: "0.4 MB/s" },
  { id: "cpu", label: "Game CPU", group: "CPU", sample: "23%" },
  { id: "cpu_temp", label: "CPU Temp", group: "CPU", soon: true, sample: "64°C" },
  { id: "gpu", label: "GPU", group: "GPU", soon: true, sample: "34%" },
  { id: "gpu_temp", label: "GPU Temp", group: "GPU", soon: true, sample: "72°C" },
  { id: "ram", label: "Game RAM", group: "RAM", sample: "1.4 GB" },
  { id: "disk", label: "Disk", group: "Hard Disk", soon: true, sample: "2%" },
];

export const MAX_OVERLAY_METRICS = 12;

export const OVERLAY_METRIC_GROUPS = [
  "Basic",
  "CPU",
  "GPU",
  "RAM",
  "Hard Disk",
] as const;

const META_BY_ID = new Map(OVERLAY_METRICS.map((m) => [m.id, m]));

export function metricMeta(id: OverlayMetric): OverlayMetricMeta | undefined {
  return META_BY_ID.get(id);
}

export function supportedOverlayMetrics(metrics: readonly OverlayMetric[]): OverlayMetric[] {
  return [...new Set(metrics)].filter(id => { const meta = metricMeta(id); return meta && !meta.soon; }).slice(0, MAX_OVERLAY_METRICS);
}

/** Sample values keyed by metric id, for the preview. */
export const OVERLAY_SAMPLE_VALUES: Record<OverlayMetric, string> =
  Object.fromEntries(
    OVERLAY_METRICS.map((m) => [m.id, m.sample]),
  ) as Record<OverlayMetric, string>;

export const OVERLAY_COLORS = [
  "#fafafa",
  "#ef4444",
  "#f59e0b",
  "#84cc16",
  "#34d39a",
  "#38bdf8",
] as const;
