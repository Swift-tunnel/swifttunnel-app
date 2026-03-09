export function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split("")
    .map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join("");
}

const LATENCY_TIERS = [
  { max: 30, text: "Excellent", color: "var(--color-latency-excellent)" },
  { max: 60, text: "Good", color: "var(--color-latency-good)" },
  { max: 100, text: "Fair", color: "var(--color-latency-fair)" },
  { max: 150, text: "Poor", color: "var(--color-latency-poor)" },
] as const;
const LATENCY_BAD = { text: "Bad", color: "var(--color-latency-bad)" };
const LATENCY_NULL = { text: "", color: "var(--color-text-muted)" };

export function getLatencyColor(ms: number | null): string {
  if (ms === null) return LATENCY_NULL.color;
  return (LATENCY_TIERS.find((t) => ms < t.max) ?? LATENCY_BAD).color;
}

export function getLatencyLabel(ms: number | null): {
  text: string;
  color: string;
} {
  if (ms === null) return LATENCY_NULL;
  return LATENCY_TIERS.find((t) => ms < t.max) ?? LATENCY_BAD;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}
