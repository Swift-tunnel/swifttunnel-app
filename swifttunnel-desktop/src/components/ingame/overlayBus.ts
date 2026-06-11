import { emitTo } from "@tauri-apps/api/event";
import type {
  OverlayMetric,
  OverlayPosition,
  OverlaySize,
  OverlayStyle,
} from "../../lib/types";

export const OVERLAY_STATS_WINDOW = "overlay-stats";
export const OVERLAY_RENDER_EVENT = "overlay-render";

/** Snapshot the main window emits to the stats overlay window each tick. */
export interface OverlayRenderPayload {
  enabled: boolean;
  metrics: OverlayMetric[];
  size: OverlaySize;
  color: string;
  style: OverlayStyle;
  position: OverlayPosition;
  values: Partial<Record<OverlayMetric, string>>;
}

export async function pushOverlayRender(
  payload: OverlayRenderPayload,
): Promise<void> {
  await emitTo(OVERLAY_STATS_WINDOW, OVERLAY_RENDER_EVENT, payload);
}
