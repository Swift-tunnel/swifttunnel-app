export function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split("")
    .map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join("");
}

export function getLatencyColor(ms: number | null): string {
  if (ms === null) return "var(--color-text-muted)";
  if (ms < 30) return "var(--color-latency-excellent)";
  if (ms < 60) return "var(--color-latency-good)";
  if (ms < 100) return "var(--color-latency-fair)";
  if (ms < 150) return "var(--color-latency-poor)";
  return "var(--color-latency-bad)";
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}
