import type { WindowState } from "./types";

export const MIN_WINDOW_WIDTH = 900;
export const MIN_WINDOW_HEIGHT = 600;
/** Must track maxWidth/maxHeight for the "main" window in tauri.conf.json.
 *  Without clamping here, a size saved before the cap existed is restored
 *  verbatim on the next launch and silently defeats it. */
export const MAX_WINDOW_WIDTH = 1360;
export const MAX_WINDOW_HEIGHT = 860;

export type MonitorWorkArea = {
  x: number;
  y: number;
  width: number;
  height: number;
};

const DEFAULT_TITLEBAR_HEIGHT = 64;
const DEFAULT_VISIBLE_MARGIN = 64;

export function isPersistableWindowSize(width: number, height: number): boolean {
  return (
    Number.isFinite(width) &&
    Number.isFinite(height) &&
    width >= MIN_WINDOW_WIDTH &&
    height >= MIN_WINDOW_HEIGHT
  );
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

export function normalizeWindowState(state: WindowState): WindowState {
  const x = state.x !== null && Number.isFinite(state.x) ? state.x : null;
  const y = state.y !== null && Number.isFinite(state.y) ? state.y : null;
  const width = Number.isFinite(state.width)
    ? clamp(state.width, MIN_WINDOW_WIDTH, MAX_WINDOW_WIDTH)
    : MIN_WINDOW_WIDTH;
  const height = Number.isFinite(state.height)
    ? clamp(state.height, MIN_WINDOW_HEIGHT, MAX_WINDOW_HEIGHT)
    : MIN_WINDOW_HEIGHT;

  return {
    ...state,
    x,
    y,
    width,
    height,
    maximized: state.maximized === true,
  };
}

export function ensureWindowStateVisible(
  state: WindowState,
  monitors: MonitorWorkArea[],
  options?: {
    primaryMonitor?: MonitorWorkArea;
    titlebarHeight?: number;
    visibleMargin?: number;
  },
): WindowState {
  if (state.x === null || state.y === null) return state;
  if (!Number.isFinite(state.x) || !Number.isFinite(state.y)) {
    return { ...state, x: null, y: null };
  }
  if (monitors.length === 0) return state;

  const titlebarHeight = Math.max(
    1,
    options?.titlebarHeight ?? DEFAULT_TITLEBAR_HEIGHT,
  );
  const titlebarRect: MonitorWorkArea = {
    x: state.x,
    y: state.y,
    width: state.width,
    height: Math.min(state.height, titlebarHeight),
  };
  const visibleMargin = Math.max(
    0,
    options?.visibleMargin ?? DEFAULT_VISIBLE_MARGIN,
  );

  // A single visible border pixel is not a usable drag handle. Require a
  // reachable strip on at least one display before restoring this position.
  const isTitlebarVisible = monitors.some((monitor) => {
    if (monitor.width <= 0 || monitor.height <= 0) return false;
    const width = Math.min(titlebarRect.x + titlebarRect.width, monitor.x + monitor.width)
      - Math.max(titlebarRect.x, monitor.x);
    const height = Math.min(titlebarRect.y + titlebarRect.height, monitor.y + monitor.height)
      - Math.max(titlebarRect.y, monitor.y);
    return width >= Math.min(titlebarRect.width, monitor.width, Math.max(1, visibleMargin))
      && height >= Math.min(titlebarRect.height, monitor.height, 32);
  });
  if (isTitlebarVisible) return state;

  const target = options?.primaryMonitor ?? monitors[0];
  const centerX = target.x + Math.round((target.width - state.width) / 2);
  const centerY = target.y + Math.round((target.height - state.height) / 2);

  const minX = target.x - state.width + visibleMargin;
  const maxX = target.x + target.width - visibleMargin;
  const minY = target.y;
  const maxY = target.y + Math.max(0, target.height - titlebarHeight);

  return {
    ...state,
    x: maxX >= minX ? clamp(centerX, minX, maxX) : centerX,
    y: maxY >= minY ? clamp(centerY, minY, maxY) : centerY,
  };
}
