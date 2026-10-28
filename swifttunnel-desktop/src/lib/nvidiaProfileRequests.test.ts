import { beforeEach, expect, it, vi } from "vitest";
import type { NvidiaDriverProfile } from "./types";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { gamesNvidiaProfile, gamesSaveNvidia } from "./commands";
const oldProfile: NvidiaDriverProfile = { available: true, writable: true, reason: null, settings: [{ id: 1, current: 0, override_value: 0 }] };
const nextProfile: NvidiaDriverProfile = { ...oldProfile, settings: [{ id: 1, current: 1, override_value: 1 }] };
function deferred() {
  let resolve!: (profile: NvidiaDriverProfile) => void, reject!: (error: Error) => void;
  const promise = new Promise<NvidiaDriverProfile>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}
beforeEach(() => { h.invoke.mockReset().mockResolvedValue(nextProfile); });

it("makes a reopened panel read after a pending Apply, instead of displaying an older profile", async () => {
  const pending = deferred();
  let saved = false;
  h.invoke.mockImplementation((command: string) => command === "games_save_nvidia"
    ? pending.promise.then(result => { saved = true; return result; }) : Promise.resolve(saved ? nextProfile : oldProfile));
  const saving = gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings);
  const reading = gamesNvidiaProfile();
  pending.resolve(nextProfile);
  await saving;
  expect(await reading).toEqual(nextProfile);
});

it("waits for an existing profile read before starting the driver write", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_nvidia_profile" ? pending.promise : Promise.resolve(nextProfile));
  const reading = gamesNvidiaProfile();
  const saving = gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings);
  const beforeRead = h.invoke.mock.calls.map(call => call[0]);
  pending.resolve(oldProfile);
  await Promise.all([reading, saving]);
  expect(beforeRead).toEqual(["games_nvidia_profile"]);
});

it("does not reuse the pre-write read when the panel reopens during a queued Apply", async () => {
  const pending = deferred(); let reads = 0;
  h.invoke.mockImplementation((command: string) => command === "games_nvidia_profile" && ++reads === 1
    ? pending.promise : Promise.resolve(nextProfile));
  const firstRead = gamesNvidiaProfile();
  const saving = gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings);
  const reopened = gamesNvidiaProfile();
  pending.resolve(oldProfile);
  await expect(firstRead).resolves.toEqual(oldProfile);
  await saving;
  await expect(reopened).resolves.toEqual(nextProfile);
  expect(h.invoke.mock.calls.map(call => call[0])).toEqual(["games_nvidia_profile", "games_save_nvidia", "games_nvidia_profile"]);
});

it("refuses a competing Apply and allows reads and retry after a failed write", async () => {
  const pending = deferred();
  h.invoke.mockImplementation((command: string) => command === "games_save_nvidia" ? pending.promise : Promise.resolve(oldProfile));
  const saving = gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings).catch(String);
  const duplicate = gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings).then(() => null, String);
  const reading = gamesNvidiaProfile();
  pending.reject(new Error("Driver profile could not be saved. Retry Apply."));
  await saving;
  expect(await duplicate).toContain("still being applied");
  expect(await reading).toEqual(oldProfile);
  h.invoke.mockResolvedValue(nextProfile);
  await expect(gamesSaveNvidia([{ id: 1, value: 1 }], oldProfile.settings)).resolves.toEqual(nextProfile);
});
