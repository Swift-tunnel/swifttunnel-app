import { describe, expect, it, vi } from "vitest";
import { invoke } from "./tauri-core";
import type { RobloxLibrarySnapshot } from "../lib/types";

describe("browser demo backend", () => {
  it("answers the Games page from its fixture service instead of undefined", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const library = await invoke<RobloxLibrarySnapshot>("games_get_library");
      expect(library.entries.length).toBeGreaterThan(0);
      expect(await invoke("games_startup_target")).toBeNull();
      // Handlers the demo already has still win over the fixture service.
      expect(await invoke("games_installed_clients")).toEqual(["standard"]);
      expect(warn).not.toHaveBeenCalled();
    } finally { warn.mockRestore(); }
  });
});
