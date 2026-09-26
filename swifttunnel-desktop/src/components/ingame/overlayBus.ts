import { emitTo } from "@tauri-apps/api/event";
import type {
  OverlayMetric,
  OverlayPosition,
  OverlaySize,
  OverlayStyle,
} from "../../lib/types";

export const OVERLAY_STATS_WINDOW = "overlay-stats";
export const OVERLAY_RENDER_EVENT = "overlay-render";
/** overlay -> main: user dragged the bar to (x, y) px from the monitor corner. */
export const OVERLAY_POSITION_EVENT = "overlay-position";

/** Snapshot the main window emits to the stats overlay window each tick. */
export interface OverlayRenderPayload {
  enabled: boolean;
  /** Explicit disable or unavailable metrics must also cancel interaction. */
  forceHide: boolean;
  metrics: OverlayMetric[];
  size: OverlaySize;
  color: string;
  style: OverlayStyle;
  position: OverlayPosition;
  customX: number | null;
  customY: number | null;
  values: Partial<Record<OverlayMetric, string>>;
}

export function overlayMayInteract(payload: OverlayRenderPayload | null): boolean {
  return !!payload && !payload.forceHide && payload.metrics.length > 0;
}

export function overlayShouldShow(payload: OverlayRenderPayload | null, interacting: boolean): boolean {
  return overlayMayInteract(payload) && (!!payload?.enabled || interacting);
}

export interface OverlayPositionPayload {
  x: number;
  y: number;
}

export async function pushOverlayRender(
  payload: OverlayRenderPayload,
): Promise<void> {
  await emitTo(OVERLAY_STATS_WINDOW, OVERLAY_RENDER_EVENT, payload);
}

export async function emitOverlayPosition(x: number, y: number): Promise<void> {
  await emitTo("main", OVERLAY_POSITION_EVENT, { x, y });
}
