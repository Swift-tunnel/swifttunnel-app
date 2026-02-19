import type { WindowState } from "./types";

export const MIN_WINDOW_WIDTH = 800;
export const MIN_WINDOW_HEIGHT = 600;

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

export function normalizeWindowState(state: WindowState): WindowState {
  const x = state.x !== null && Number.isFinite(state.x) ? state.x : null;
  const y = state.y !== null && Number.isFinite(state.y) ? state.y : null;
  const width = Number.isFinite(state.width)
    ? Math.max(state.width, MIN_WINDOW_WIDTH)
    : MIN_WINDOW_WIDTH;
  const height = Number.isFinite(state.height)
    ? Math.max(state.height, MIN_WINDOW_HEIGHT)
    : MIN_WINDOW_HEIGHT;

  return {
    ...state,
    x,
    y,
    width,
    height,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function rectsIntersect(a: MonitorWorkArea, b: MonitorWorkArea): boolean {
  if (a.width <= 0 || a.height <= 0 || b.width <= 0 || b.height <= 0) return false;

  return (
    a.x < b.x + b.width &&
    a.x + a.width > b.x &&
    a.y < b.y + b.height &&
    a.y + a.height > b.y
  );
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

  const isTitlebarVisible = monitors.some((monitor) =>
    rectsIntersect(titlebarRect, monitor),
  );
  if (isTitlebarVisible) return state;

  const target = options?.primaryMonitor ?? monitors[0];
  const centerX = target.x + Math.round((target.width - state.width) / 2);
  const centerY = target.y + Math.round((target.height - state.height) / 2);

  const visibleMargin = Math.max(
    0,
    options?.visibleMargin ?? DEFAULT_VISIBLE_MARGIN,
  );

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
