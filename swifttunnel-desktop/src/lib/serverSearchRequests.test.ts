import { beforeEach, expect, it, vi } from "vitest";
import type { RobloxServerPage } from "./types";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { gamesSearchServers } from "./commands";
function deferred() {
  let resolve!: (page: RobloxServerPage) => void, reject!: (error: Error) => void;
  const promise = new Promise<RobloxServerPage>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
const page: RobloxServerPage = { servers: [], next_cursor: null, warning: null };
beforeEach(() => { h.invoke.mockReset().mockResolvedValue(page); });

it("shares an identical pending server search across repeated clicks or dialog remounts", async () => {
  const pending = deferred(); h.invoke.mockReturnValue(pending.promise);
  const first = gamesSearchServers("1818", 7);
  const second = gamesSearchServers("1818", 7);
  const calls = h.invoke.mock.calls.length;
  pending.resolve(page);
  await expect(first).resolves.toEqual(page);
  await expect(second).resolves.toEqual(page);
  expect(calls).toBe(1);
});

it("does not merge different games, locations or pages", async () => {
  await Promise.all([gamesSearchServers("1818", 7), gamesSearchServers("1819", 7),
    gamesSearchServers("1818", 8), gamesSearchServers("1818", 7, 100)]);
  expect(h.invoke).toHaveBeenCalledTimes(4);
});

it("releases failed and successful searches so a later refresh stays fresh", async () => {
  const pending = deferred(); h.invoke.mockReturnValueOnce(pending.promise);
  const first = gamesSearchServers("1818", 7).catch(String);
  const second = gamesSearchServers("1818", 7).catch(String);
  pending.reject(new Error("Server directory unavailable. Retry."));
  await Promise.all([first, second]);
  h.invoke.mockResolvedValue(page);
  const failedCalls = h.invoke.mock.calls.length;
  await gamesSearchServers("1818", 7);
  await gamesSearchServers("1818", 7);
  expect(failedCalls).toBe(1);
  expect(h.invoke).toHaveBeenCalledTimes(3);
});
