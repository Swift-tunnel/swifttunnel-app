import { describe, expect, it } from "vitest";

import { LITE_DEFAULT_TAB, LITE_TABS } from "./lite";
import { NAV_SECTIONS } from "../components/shell/nav";

/**
 * These run against a full build, where `IS_LITE` is false, so they cannot
 * assert what Lite renders. What they can do is keep `LITE_TABS` honest, which
 * is where drift would actually cause harm: the settings store uses it to
 * decide whether a persisted tab is one this build can show, so a stale id
 * there means Lite opens on a blank screen for anyone whose last session in
 * the full app ended on a page Lite does not have.
 */
describe("the Lite tab list", () => {
  it("opens on a page it keeps", () => {
    expect(LITE_TABS).toContain(LITE_DEFAULT_TAB);
  });

  it("names only tabs the app actually has", () => {
    const real = new Set(NAV_SECTIONS.flatMap((s) => s.items).map((i) => i.id));
    const unknown = LITE_TABS.filter((tab) => !real.has(tab));
    expect(unknown).toEqual([]);
  });

  it("stays at three pages", () => {
    // Lite's nav divides a 380px bar three ways. A fourth tab is a layout
    // change, not a list change, so it should not be possible to add one here
    // without the test that says so going red.
    expect(LITE_TABS).toHaveLength(3);
  });
});
