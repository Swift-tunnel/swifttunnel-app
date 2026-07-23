import { describe, expect, it } from "vitest";
import { SEARCH_ENTRIES, searchEntries } from "./searchIndex";

/** Every component source, as raw text — used to prove anchors are real. */
const SOURCES = import.meta.glob<string>("../components/**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
});

function allSourceText(): string {
  return Object.values(SOURCES).join("\n");
}

describe("search index", () => {
  it("has no duplicate ids", () => {
    const ids = SEARCH_ENTRIES.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  // The bug this guards: entries drift when a control is renamed or moved, and
  // search silently navigates to a tab without revealing anything.
  it("points every anchor at a target that exists in the UI", () => {
    const src = allSourceText();
    const missing = SEARCH_ENTRIES.filter((e) => e.anchor).filter(
      (e) =>
        !src.includes(`data-search-anchor="${e.anchor}"`) &&
        !src.includes(`anchorId="${e.anchor}"`) &&
        // Optimize/Speed Up cards render the catalog id dynamically.
        !src.includes(`data-search-anchor={def.id}`),
    );
    expect(missing.map((e) => `${e.label} → ${e.anchor}`)).toEqual([]);
  });

  it("finds controls by the words users actually type", () => {
    const top = (q: string) => searchEntries(q).map((e) => e.label);

    // Symptoms, not feature names.
    expect(top("wifi")).toContain("Run Repair");
    expect(top("no internet")).toContain("Run Repair");
    expect(top("hotkey")).toContain("Overlay hotkey");
    expect(top("fps counter")).toContain("Overlay metrics");
    expect(top("uninstall")).toContain("Uninstall SwiftTunnel");
    expect(top("startup")).toContain("Run on startup");
    expect(top("download speed")).toContain("Speed test");
    expect(top("packet loss")).toContain("Stability test");
    expect(top("discord")).toContain("Discord Rich Presence");
    expect(top("region")).toContain("Change region");
  });

  it("returns the page list for an empty query", () => {
    const empty = searchEntries("");
    expect(empty.length).toBeGreaterThan(0);
    expect(empty.every((e) => e.section === "Go to page")).toBe(true);
  });
});
