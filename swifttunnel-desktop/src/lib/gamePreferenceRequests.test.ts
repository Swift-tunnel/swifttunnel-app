import { beforeEach, expect, it, vi } from "vitest";
import type { GamePreferences } from "./types";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { gamesForget, gamesGetLibrary, gamesLaunchPlan, gamesSaveLauncherConfig, gamesSetPreferences } from "./commands";
import type { LauncherConfig } from "./types";

const preferences: GamePreferences = { datacenter_id: 7, fps_cap: 400, graphics_quality: null, use_tunnel: true };
function deferred() {
  let resolve!: () => void, reject!: (error: Error) => void;
  const promise = new Promise<void>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(() => { h.invoke.mockReset().mockResolvedValue(undefined); });

it("waits for the game's save before reopening the library or planning Play", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_set_preferences" ? pending.promise : Promise.resolve(undefined));
  const saving = gamesSetPreferences("1818", "standard", preferences);
  const reading = gamesGetLibrary();
  const planning = gamesLaunchPlan("1818", "standard");
  // Let async wrappers reach their native IPC boundary.
  for (let i = 0; i < 8; i++) await Promise.resolve();
  const beforeSave = h.invoke.mock.calls.map(call => call[0]);
  pending.resolve();
  await Promise.all([saving, reading, planning]);
  expect(beforeSave).toEqual(["games_set_preferences"]);
  expect(h.invoke.mock.calls.map(call => call[0])).toContain("games_launch_plan");
});

it("rejects overlapping writes and allows a retry after the active save completes", async () => {
  const pending = deferred(); h.invoke.mockReturnValue(pending.promise);
  const saving = gamesSetPreferences("1818", "standard", preferences);
  const duplicate = gamesSetPreferences("1818", "standard", { ...preferences, fps_cap: 600 }).then(() => null, String);
  pending.resolve(); await saving;
  expect(await duplicate).toContain("still being saved");
  expect(h.invoke).toHaveBeenCalledTimes(1);
  h.invoke.mockResolvedValue(undefined);
  await gamesSetPreferences("1818", "standard", { ...preferences, fps_cap: 600 });
  expect(h.invoke).toHaveBeenCalledTimes(2);
});

it("does not launch with old preferences after a failed save, but lets the library reload", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_set_preferences" ? pending.promise : Promise.resolve(undefined));
  const saving = gamesSetPreferences("1818", "standard", preferences).catch(String);
  const planning = gamesLaunchPlan("1818", "standard").then(() => null, String);
  const reading = gamesGetLibrary();
  pending.reject(new Error("Could not save game settings. Retry Save."));
  await saving;
  expect(await planning).toContain("Retry Save");
  await reading;
  expect(h.invoke.mock.calls.some(call => call[0] === "games_launch_plan")).toBe(false);
});

it("forgets a game only after its pending save finishes, so it cannot reappear", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_set_preferences" ? pending.promise : Promise.resolve(undefined));
  const saving = gamesSetPreferences("1818", "standard", preferences);
  const forgetting = gamesForget("1818", "standard");
  for (let i = 0; i < 8; i++) await Promise.resolve();
  const beforeSave = h.invoke.mock.calls.map(call => call[0]);
  pending.resolve(); await Promise.all([saving, forgetting]);
  expect(beforeSave).toEqual(["games_set_preferences"]);
  expect(h.invoke.mock.calls[1][0]).toBe("games_forget");
});

it("observes a failed game save even while a Matchmaker save is also pending", async () => {
  const matchmaker = deferred(), game = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_save_launcher_config" ? matchmaker.promise
    : command === "games_set_preferences" ? game.promise : Promise.resolve(undefined));
  const globalSave = gamesSaveLauncherConfig({} as LauncherConfig);
  const gameSave = gamesSetPreferences("1818", "standard", preferences).catch(String);
  const planning = gamesLaunchPlan("1818", "standard").then(() => null, String);
  game.reject(new Error("Could not save game settings. Retry Save."));
  await gameSave;
  matchmaker.resolve(); await globalSave;
  expect(await planning).toContain("Retry Save");
  expect(h.invoke.mock.calls.some(call => call[0] === "games_launch_plan")).toBe(false);
});
