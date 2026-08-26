import { describe, expect, it } from "vitest";

import { LITE_DEFAULT_TAB, LITE_HIDDEN_BOOST_ANCHORS, LITE_TABS } from "./lite";
import { SEARCH_ENTRIES } from "./searchIndex";
import { NAV_SECTIONS } from "../components/shell/nav";

/**
 * These run against a full build, where `IS_LITE` is false, so they cannot
 * assert what Lite renders. What they can do is keep the Lite lists honest
 * against the real index, which is where the drift would actually happen: a
 * setting gets renamed or moved and the Lite filter quietly stops matching it.
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
});

describe("the hidden boost anchors", () => {
  it("all exist in the search index", () => {
    // A typo here is invisible at runtime: the entry simply fails to match and
    // Lite goes on offering a setting that is on none of its pages.
    const known = new Set(
      SEARCH_ENTRIES.map((entry) => entry.anchor).filter(Boolean),
    );
    const missing = [...LITE_HIDDEN_BOOST_ANCHORS].filter(
      (anchor) => !known.has(anchor),
    );
    expect(missing).toEqual([]);
  });

  it("leaves the game and tunnel settings alone", () => {
    // The whole point of the split: Lite keeps what belongs to Roblox and to
    // the tunnel, and drops the Windows tuning.
    for (const anchor of [
      "unlock_fps",
      "ultraboost",
      "launch_fullscreen",
      "country_ban",
    ]) {
      expect(LITE_HIDDEN_BOOST_ANCHORS.has(anchor)).toBe(false);
    }
  });

  it("covers every setting in the sections Lite removes", () => {
    for (const anchor of [
      "high_priority",
      "timer_resolution",
      "mmcss",
      "game_mode",
      "disable_nagle",
      "network_throttling",
      "gpu_binding",
      "performance_cores",
      "unbind_cpu0",
    ]) {
      expect(LITE_HIDDEN_BOOST_ANCHORS.has(anchor)).toBe(true);
    }
  });
});
