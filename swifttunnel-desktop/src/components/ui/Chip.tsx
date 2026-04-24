import type { ReactNode } from "react";

type Tone = "neutral" | "accent" | "connected" | "warning" | "error" | "custom";

interface ChipProps {
  children: ReactNode;
  tone?: Tone;
  color?: string;
  mono?: boolean;
  size?: "xs" | "sm";
  uppercase?: boolean;
}

function toneStyle(tone: Tone, color?: string): React.CSSProperties {
  if (tone === "custom" && color) {
    return { backgroundColor: `${color}18`, color };
  }
  switch (tone) {
    case "accent":
      return {
        backgroundColor: "var(--color-accent-primary-soft-15)",
        color: "var(--color-accent-secondary)",
      };
    case "connected":
      return {
        backgroundColor: "rgba(34, 197, 94, 0.15)",
        color: "var(--color-status-connected)",
      };
    case "warning":
      return {
        backgroundColor: "var(--color-status-warning-soft-10)",
        color: "var(--color-status-warning)",
      };
    case "error":
      return {
        backgroundColor: "var(--color-status-error-soft-10)",
        color: "var(--color-status-error)",
      };
    case "neutral":
    default:
      return {
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-muted)",
      };
  }
}

export function Chip({
  children,
  tone = "neutral",
  color,
  mono,
  size = "sm",
  uppercase,
}: ChipProps) {
  const sizeClass =
    size === "xs"
      ? "text-[9px] px-1.5 py-0.5"
      : "text-[10.5px] px-2 py-0.5";

  return (
    <span
      className={`inline-flex items-center rounded-[3px] font-semibold ${sizeClass} ${mono ? "font-mono" : ""} ${uppercase ? "uppercase tracking-[0.1em]" : ""}`}
      style={toneStyle(tone, color)}
    >
      {children}
    </span>
  );
}
