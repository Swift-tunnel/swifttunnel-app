import { describe, expect, it } from "vitest";
import { createStore } from "zustand/vanilla";

import { PAUSED_VALUE, liveSelector } from "./useLiveUpdates";

describe("liveSelector", () => {
  it("follows the store while live", () => {
    const store = createStore(() => ({ ping: 20 }));
    const select = liveSelector(true, (s: { ping: number }) => s.ping);
    expect(select(store.getState())).toBe(20);
    store.setState({ ping: 25 });
    expect(select(store.getState())).toBe(25);
  });

  it("gives every write the same snapshot while paused, so nothing re-renders", () => {
    const store = createStore(() => ({ ping: 20 }));
    const select = liveSelector(false, (s: { ping: number }) => s.ping);
    const before = select(store.getState());
    for (const ping of [21, 19, 40]) {
      store.setState({ ping });
      // React compares snapshots with Object.is; an equal one skips the render.
      expect(Object.is(select(store.getState()), before)).toBe(true);
    }
    expect(before).toBe(PAUSED_VALUE);
  });
});
