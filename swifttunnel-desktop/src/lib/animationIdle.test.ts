import { describe, expect, it, vi } from "vitest";
import {
  IDLE_CLASS,
  applyAnimationIdle,
  installAnimationIdle,
  shouldPauseAnimations,
} from "./animationIdle";


/** Minimal stand-in for an element's classList; the suite has no DOM. */
function fakeRoot() {
  const classes = new Set<string>();
  return {
    classes,
    classList: {
      toggle(token: string, force?: boolean) {
        const on = force ?? !classes.has(token);
        if (on) classes.add(token);
        else classes.delete(token);
        return on;
      },
      remove(token: string) {
        classes.delete(token);
      },
    },
    has(token: string) {
      return classes.has(token);
    },
  };
}

describe("shouldPauseAnimations", () => {
  it("pauses when the window loses focus", () => {
    expect(
      shouldPauseAnimations({ idleWhenUnfocused: true, hasFocus: false }),
    ).toBe(true);
  });

  it("runs while the window is in front", () => {
    expect(
      shouldPauseAnimations({ idleWhenUnfocused: true, hasFocus: true }),
    ).toBe(false);
  });

  it("never pauses when the setting is off", () => {
    // Someone watching the graph on a second monitor opted out deliberately.
    expect(
      shouldPauseAnimations({ idleWhenUnfocused: false, hasFocus: false }),
    ).toBe(false);
  });
});

describe("applyAnimationIdle", () => {
  it("adds and removes the class", () => {
    const root = fakeRoot();

    applyAnimationIdle(root, true);
    expect(root.has(IDLE_CLASS)).toBe(true);

    applyAnimationIdle(root, false);
    expect(root.has(IDLE_CLASS)).toBe(false);
  });
});

describe("installAnimationIdle", () => {
  function harness(hasFocus: boolean, idleEnabled = true) {
    const listeners = new Map<string, EventListener>();
    const root = fakeRoot();
    let focused = hasFocus;

    const target = {
      addEventListener: vi.fn((t: string, fn: EventListener) => {
        listeners.set(t, fn);
      }),
      removeEventListener: vi.fn((t: string) => listeners.delete(t)),
    } as unknown as Window;

    const doc = {
      hasFocus: () => focused,
      addEventListener: vi.fn((t: string, fn: EventListener) => {
        listeners.set(t, fn);
      }),
      removeEventListener: vi.fn((t: string) => listeners.delete(t)),
    } as unknown as Document;

    const dispose = installAnimationIdle({
      isIdleEnabled: () => idleEnabled,
      root,
      target,
      doc,
    });

    return {
      root,
      dispose,
      listeners,
      setFocus(v: boolean) {
        focused = v;
      },
    };
  }

  it("applies the current state immediately on install", () => {
    // A window that starts in the background should not animate for a frame
    // before the first blur event arrives.
    expect(harness(false).root.has(IDLE_CLASS)).toBe(true);
    expect(harness(true).root.has(IDLE_CLASS)).toBe(false);
  });

  it("pauses on blur and resumes on focus", () => {
    const h = harness(true);
    expect(h.root.has(IDLE_CLASS)).toBe(false);

    h.setFocus(false);
    h.listeners.get("blur")!({} as Event);
    expect(h.root.has(IDLE_CLASS)).toBe(true);

    h.setFocus(true);
    h.listeners.get("focus")!({} as Event);
    expect(h.root.has(IDLE_CLASS)).toBe(false);
  });

  it("also reacts to the document being hidden", () => {
    const h = harness(true);

    h.setFocus(false);
    h.listeners.get("visibilitychange")!({} as Event);

    expect(h.root.has(IDLE_CLASS)).toBe(true);
  });

  it("leaves motion alone when the setting is off", () => {
    const h = harness(false, false);
    expect(h.root.has(IDLE_CLASS)).toBe(false);
  });

  it("clears the class when disposed", () => {
    const h = harness(false);
    expect(h.root.has(IDLE_CLASS)).toBe(true);

    h.dispose();

    expect(h.root.has(IDLE_CLASS)).toBe(false);
    expect(h.listeners.size).toBe(0);
  });
});
