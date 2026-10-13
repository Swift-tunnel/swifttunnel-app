import type { OverlayPosition } from "../../lib/types";
export interface OverlayMonitor {
  x: number;
  y: number;
  w: number;
  h: number;
  scale: number;
}
export function validOverlayMonitor(
  m: OverlayMonitor | null | undefined,
): m is OverlayMonitor {
  return (
    !!m &&
    [m.x, m.y, m.w, m.h, m.scale].every(Number.isFinite) &&
    m.w > 0 &&
    m.h > 0 &&
    m.scale >= 0.5 &&
    m.scale <= 8
  );
}
export function clampOverlayPosition(
  m: OverlayMonitor,
  size: { w: number; h: number },
  x: number,
  y: number,
) {
  return {
    x: Math.round(
      Math.max(
        m.x,
        Math.min(m.x + Math.max(0, m.w - size.w), Number.isFinite(x) ? x : m.x),
      ),
    ),
    y: Math.round(
      Math.max(
        m.y,
        Math.min(m.y + Math.max(0, m.h - size.h), Number.isFinite(y) ? y : m.y),
      ),
    ),
  };
}
export function overlayAnchor(
  m: OverlayMonitor,
  size: { w: number; h: number },
  position: OverlayPosition,
  customX: number | null,
  customY: number | null,
) {
  if (customX !== null && customY !== null)
    return clampOverlayPosition(m, size, m.x + customX, m.y + customY);
  const [v, h = "center"] = position.split("-");
  const margin = 22 * m.scale;
  return clampOverlayPosition(
    m,
    size,
    h === "left"
      ? m.x + margin
      : h === "right"
        ? m.x + m.w - size.w - margin
        : m.x + (m.w - size.w) / 2,
    v === "top"
      ? m.y + margin
      : v === "bottom"
        ? m.y + m.h - size.h - margin
        : m.y + (m.h - size.h) / 2,
  );
}
export function overlayHeartbeatExpired(last: number, now: number) {
  return last > 0 && now - last > 4500;
}
