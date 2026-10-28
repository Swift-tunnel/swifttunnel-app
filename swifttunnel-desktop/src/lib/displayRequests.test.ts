import { beforeEach, expect, it, vi } from "vitest";
import type { GameDisplay } from "./types";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { gamesDisplays } from "./commands";
const displays: GameDisplay[] = [{ id: "display-one", left: 0, top: 0, width: 1920, height: 1080, primary: true }];
beforeEach(() => h.invoke.mockReset().mockResolvedValue(displays));

it("shares pending display discovery through dialog remounts but checks again on a later open", async () => {
  let finish!: (value: GameDisplay[]) => void;
  h.invoke.mockReturnValueOnce(new Promise<GameDisplay[]>(resolve => { finish = resolve; }));
  const first = gamesDisplays(), second = gamesDisplays();
  const calls = h.invoke.mock.calls.length;
  finish(displays); await Promise.all([first, second]);
  expect(calls).toBe(1);
  await gamesDisplays();
  expect(h.invoke).toHaveBeenCalledTimes(2);
});

it("releases a failed display query so reopening can retry", async () => {
  h.invoke.mockRejectedValueOnce(new Error("Display discovery unavailable"));
  await expect(gamesDisplays()).rejects.toThrow("unavailable");
  await expect(gamesDisplays()).resolves.toEqual(displays);
});
