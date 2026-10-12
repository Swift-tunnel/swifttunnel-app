import { describe, expect, it } from "vitest";
import { SEARCH_ENTRIES, searchEntries } from "./searchIndex";

/** Every component source, as raw text, used to prove anchors are real. */
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
    const missing = SEARCH_ENTRIES.filter((e) => e.anchor).filter((e) => {
      // Optimize/Speed Up cards render the catalog id dynamically. Only those
      // entries get this pass: applied to all, it would excuse every anchor.
      if (e.id.startsWith("opt-") || e.id.startsWith("su-")) {
        return !src.includes(`data-search-anchor={def.id}`);
      }
      return (
        !src.includes(`data-search-anchor="${e.anchor}"`) &&
        !src.includes(`anchorId="${e.anchor}"`) &&
        // Passed down as a prop (Diagnostics tests) or from a table (NVIDIA rows).
        !src.includes(`anchor="${e.anchor}"`) &&
        !src.includes(`anchor:"${e.anchor}"`)
      );
    });
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

    // Features added since the index was first written.
    expect(top("fastflags")).toContain("FastFlags editor");
    expect(top("vulkan")).toContain("Graphics renderer");
    expect(top("vsync")).toContain("NVIDIA vertical sync");
    expect(top("bloxstrap")).toContain("Import launcher settings");
    expect(top("server")).toContain("Find a server");
    expect(top("favourites")).toContain("Game library");
    expect(top("ram")).toContain("Clean RAM");
    expect(top("ethernet")).toContain("Network adapter");
    expect(top("error 279").some((label) => label.includes("error 279"))).toBe(true);
  });

  it("returns the page list for an empty query", () => {
    const empty = searchEntries("");
    expect(empty.length).toBeGreaterThan(0);
    expect(empty.every((e) => e.section === "Go to page")).toBe(true);
  });
});
