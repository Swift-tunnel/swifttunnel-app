import type { CSSProperties } from "react";
import { Icon, type IconName } from "./Icon";

export interface WatermarkProps {
  icon: IconName;
  /** The corner or edge the mark bleeds off. */
  at?: "bottom-right" | "right" | "top-right";
  size?: number;
  rotate?: number;
  /** Fade the mark out toward the middle of the card. */
  fade?: boolean;
  opacity?: number;
}

/**
 * A big faded icon behind a card's content, bleeding off one edge, like the
 * Roblox mark on the Connect tab's Roblox card.
 *
 * The host card needs `relative isolate`: the mark sits at a negative z-index
 * inside that stacking context, so it paints over the card's background and
 * under everything else. It is static, so it costs nothing after first paint.
 */
export function Watermark({
  icon,
  at = "bottom-right",
  size = 150,
  rotate = 0,
  fade = false,
  opacity = 0.05,
}: WatermarkProps) {
  const place: CSSProperties =
    at === "right"
      ? {
          right: -size * 0.2,
          top: "50%",
          transform: `translateY(-50%) rotate(${rotate}deg)`,
        }
      : at === "top-right"
        ? { right: -size * 0.14, top: -size * 0.24, transform: `rotate(${rotate}deg)` }
        : { right: -size * 0.16, bottom: -size * 0.26, transform: `rotate(${rotate}deg)` };
  const mask = fade
    ? "linear-gradient(to left, #000 30%, transparent 92%)"
    : undefined;

  return (
    <span
      aria-hidden
      className="pointer-events-none absolute inset-0 -z-10 overflow-hidden rounded-[inherit]"
    >
      <Icon
        name={icon}
        size={size}
        active
        strokeWidth={1.4}
        className="absolute"
        style={{
          ...place,
          color: "var(--color-text-primary)",
          opacity,
          WebkitMaskImage: mask,
          maskImage: mask,
        }}
      />
    </span>
  );
}
