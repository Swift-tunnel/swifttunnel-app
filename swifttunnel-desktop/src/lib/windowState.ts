import type { WindowState } from "./types";

export const MIN_WINDOW_WIDTH = 800;
export const MIN_WINDOW_HEIGHT = 600;

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
