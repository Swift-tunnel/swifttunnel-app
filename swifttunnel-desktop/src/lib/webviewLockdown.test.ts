import { describe, expect, it, vi } from "vitest";
import {
  installWebviewLockdown,
  isDevToolsShortcut,
  shouldLockDown,
} from "./webviewLockdown";

const key = (
  k: string,
  mods: { ctrlKey?: boolean; shiftKey?: boolean } = {},
) => ({ key: k, ctrlKey: false, shiftKey: false, ...mods });

describe("isDevToolsShortcut", () => {
  it("catches F12", () => {
    expect(isDevToolsShortcut(key("F12"))).toBe(true);
  });

  it("catches the Ctrl+Shift devtools trio", () => {
    for (const k of ["i", "j", "c", "I", "J", "C"]) {
      expect(
        isDevToolsShortcut(key(k, { ctrlKey: true, shiftKey: true })),
        k,
      ).toBe(true);
    }
  });

  it("leaves ordinary editing shortcuts alone", () => {
    // Copy, paste and select-all still have to work in the login fields.
    for (const k of ["c", "v", "a", "x"]) {
      expect(isDevToolsShortcut(key(k, { ctrlKey: true })), k).toBe(false);
    }
  });

  it("does not fire on the letters without both modifiers", () => {
    expect(isDevToolsShortcut(key("i", { ctrlKey: true }))).toBe(false);
    expect(isDevToolsShortcut(key("i", { shiftKey: true }))).toBe(false);
    expect(isDevToolsShortcut(key("i"))).toBe(false);
  });
});

describe("shouldLockDown", () => {
  it("locks down release builds", () => {
    expect(shouldLockDown(false)).toBe(true);
  });

  it("leaves development builds inspectable", () => {
    // Removing devtools from a dev build would just make the app harder to
    // work on for no benefit.
    expect(shouldLockDown(true)).toBe(false);
  });
});

describe("installWebviewLockdown", () => {
  function fakeTarget() {
    const handlers = new Map<string, EventListener>();
    return {
      handlers,
      addEventListener: vi.fn((type: string, fn: EventListener) => {
        handlers.set(type, fn);
      }),
      removeEventListener: vi.fn((type: string) => {
        handlers.delete(type);
      }),
    };
  }

  it("blocks the context menu", () => {
    const target = fakeTarget();
    installWebviewLockdown(target);

    const event = { preventDefault: vi.fn() } as unknown as Event;
    target.handlers.get("contextmenu")!(event);

    expect(event.preventDefault).toHaveBeenCalled();
  });

  it("blocks a devtools keystroke but not an ordinary one", () => {
    const target = fakeTarget();
    installWebviewLockdown(target);
    const onKeyDown = target.handlers.get("keydown")!;

    const devtools = {
      key: "F12",
      ctrlKey: false,
      shiftKey: false,
      preventDefault: vi.fn(),
    } as unknown as Event;
    onKeyDown(devtools);
    expect(devtools.preventDefault).toHaveBeenCalled();

    const paste = {
      key: "v",
      ctrlKey: true,
      shiftKey: false,
      preventDefault: vi.fn(),
    } as unknown as Event;
    onKeyDown(paste);
    expect(paste.preventDefault).not.toHaveBeenCalled();
  });

  it("can be undone", () => {
    const target = fakeTarget();
    const remove = installWebviewLockdown(target);

    remove();

    expect(target.handlers.size).toBe(0);
  });
});
