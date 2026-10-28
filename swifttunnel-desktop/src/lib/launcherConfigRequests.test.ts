import { beforeEach, expect, it, vi } from "vitest";
import type { LauncherConfig } from "./types";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { gamesLauncherConfig, gamesSaveLauncherConfig, gamesLaunchPlan } from "./commands";

const config: LauncherConfig = { offer_recovery: false, matchmaker: {
  enabled: true, mode: "closest", blocked_datacenters: [], preferred_datacenter: 7,
  skipped_games: [], minimum_free_slots: 1, search_limit: 40, prepare_tunnel: true, offer_better_server: false,
} };
function deferred() {
  let resolve!: () => void, reject!: (error: Error) => void;
  const promise = new Promise<void>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(() => h.invoke.mockReset().mockResolvedValue(config));

it("waits for a pending Matchmaker save before a remount reads or Play plans", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_save_launcher_config" ? pending.promise : Promise.resolve(config));
  const saving = gamesSaveLauncherConfig(config);
  const loading = gamesLauncherConfig();
  const planning = gamesLaunchPlan("1818", "standard");
  const commandsBeforeSave = h.invoke.mock.calls.map(call => call[0]);
  pending.resolve();
  await Promise.all([saving, loading, planning]);
  expect(commandsBeforeSave).toEqual(["games_save_launcher_config"]);
  expect(h.invoke.mock.calls[0][0]).toBe("games_save_launcher_config");
  expect(h.invoke.mock.calls.slice(1).map(call => call[0]).sort()).toEqual(["games_launch_plan", "games_launcher_config"].sort());
});

it("rejects a competing save until the admitted native write finishes", async () => {
  const pending = deferred();
  h.invoke.mockReturnValue(pending.promise);
  const saving = gamesSaveLauncherConfig(config);
  const duplicate = gamesSaveLauncherConfig({ ...config, offer_recovery: true }).then(() => null, String);
  pending.resolve(); await saving;
  expect(await duplicate).toContain("still being saved");
  expect(h.invoke).toHaveBeenCalledTimes(1);
  h.invoke.mockResolvedValue(undefined);
  await gamesSaveLauncherConfig({ ...config, offer_recovery: true });
  expect(h.invoke).toHaveBeenCalledTimes(2);
});

it("does not launch using a failed save, but a fresh settings read and retry remain available", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_save_launcher_config" ? pending.promise : Promise.resolve(config));
  const saving = gamesSaveLauncherConfig(config).catch(String);
  const planning = gamesLaunchPlan("1818", "standard").then(() => null, String);
  const loading = gamesLauncherConfig();
  pending.reject(new Error("Could not save Matchmaker. Retry Save."));
  await saving;
  expect(await planning).toContain("Retry Save");
  await expect(loading).resolves.toEqual(config);
  expect(h.invoke.mock.calls.some(call => call[0] === "games_launch_plan")).toBe(false);
  h.invoke.mockResolvedValue(undefined);
  await gamesSaveLauncherConfig(config);
});
