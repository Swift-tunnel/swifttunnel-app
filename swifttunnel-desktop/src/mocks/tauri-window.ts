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
  async outerPosition() {
    return new MockPhysicalPosition(100, 100);
  }
  async outerSize() {
    return { width: 560, height: 750 };
  }
  async innerSize() {
    return { width: 560, height: 750 };
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
  async hide() {}
  async show() {}
  async close() {}
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
