// Mock @tauri-apps/api/window for browser preview

class MockPhysicalPosition {
  x: number;
  y: number;
  constructor(x: number, y: number) {
    this.x = x;
    this.y = y;
  }
}

class MockWindow {
  /** main.tsx branches on this to pick App vs the overlay roots. */
  label = "main";

  async outerPosition() {
    return new MockPhysicalPosition(100, 100);
  }
  async outerSize() {
    return { width: 1020, height: 660 };
  }
  async innerSize() {
    return { width: 1020, height: 660 };
  }
  async isMaximized() {
    return false;
  }
  async isMinimized() {
    return false;
  }
  async setSize() {}
  async setPosition() {}
  async maximize() {}
  async minimize() {}
  async toggleMaximize() {}
  /** Used after a capped maximise to re-centre the window. */
  async center() {}
  async unmaximize() {}
  async startDragging() {}
  async hide() {}
  async show() {}
  async close() {}
  /** Used by the stats overlay to toggle click-through. */
  async setIgnoreCursorEvents(ignore: boolean) {
    void ignore;
  }
  async onMoved(handler: () => void) {
    void handler;
    return () => {};
  }
  async onResized(handler: () => void) {
    void handler;
    return () => {};
  }
  async onCloseRequested(handler: () => void) {
    void handler;
    return () => {};
  }
}

const mockWindow = new MockWindow();

export function getCurrentWindow() {
  return mockWindow;
}

export function getAllWindows() {
  return [mockWindow];
}

const mockMonitor = {
  name: "Mock Monitor",
  size: { width: 1920, height: 1080 },
  position: { x: 0, y: 0 },
  scaleFactor: 1,
  workArea: {
    position: { x: 0, y: 0 },
    size: { width: 1920, height: 1040 },
  },
};

export async function availableMonitors() {
  return [mockMonitor];
}

export async function primaryMonitor() {
  return mockMonitor;
}

/**
 * Required by OverlayStatsBar. Missing this export used to fail the whole ESM
 * module graph (main.tsx imports OverlayStatsBar eagerly), which blanked the
 * page in browser-preview mode, `npm run dev` rendered nothing at all.
 */
export async function currentMonitor() {
  return mockMonitor;
}
