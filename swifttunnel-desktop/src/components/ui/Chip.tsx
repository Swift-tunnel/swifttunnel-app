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
    return {
      backgroundColor: `${color}1a`,
      color,
      border: `1px solid ${color}30`,
    };
  }
  switch (tone) {
    case "accent":
      return {
        backgroundColor: "var(--color-accent-primary-soft-12)",
        color: "var(--color-text-primary)",
        border: "1px solid var(--color-accent-primary-soft-15)",
      };
    case "connected":
      return {
        backgroundColor: "var(--color-status-connected-soft-10)",
        color: "var(--color-status-connected)",
        border: "1px solid var(--color-status-connected-soft-20)",
      };
    case "warning":
      return {
        backgroundColor: "var(--color-status-warning-soft-10)",
        color: "var(--color-status-warning)",
        border: "1px solid var(--color-status-warning-soft-20)",
      };
    case "error":
      return {
        backgroundColor: "var(--color-status-error-soft-10)",
        color: "var(--color-status-error)",
        border: "1px solid var(--color-status-error-soft-20)",
      };
    case "neutral":
    default:
      return {
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-muted)",
        border: "1px solid var(--color-border-subtle)",
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
      ? "text-[9.5px] px-1.5 py-[2px]"
      : "text-[10.5px] px-2 py-[3px]";

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-[4px] font-medium leading-none ${sizeClass} ${mono ? "font-mono" : ""} ${uppercase ? "uppercase tracking-[0.08em]" : ""}`}
      style={toneStyle(tone, color)}
    >
      {children}
    </span>
  );
}
