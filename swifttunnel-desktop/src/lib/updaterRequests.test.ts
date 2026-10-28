import { beforeEach, expect, it, vi } from "vitest";
import type { UpdaterCheckResponse } from "./types";

const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { updaterCheckChannel } from "./commands";

function deferred() {
  let resolve!: (value: UpdaterCheckResponse) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<UpdaterCheckResponse>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const result: UpdaterCheckResponse = {
  current_version: "3.9.5", available_version: null,
  release_tag: null, release_notes: null, channel: "Stable",
};
beforeEach(() => { h.invoke.mockReset(); });

it("shares an in-flight channel check but later manual checks remain fresh", async () => {
  const pending = deferred();
  h.invoke.mockReturnValue(pending.promise);
  const first = updaterCheckChannel("Stable");
  const second = updaterCheckChannel("Stable");
  const requests = h.invoke.mock.calls.length;
  pending.resolve(result);
  await Promise.all([first, second]);
  expect(requests).toBe(1);
  h.invoke.mockResolvedValue(result);
  await updaterCheckChannel("Stable");
  expect(h.invoke).toHaveBeenCalledTimes(2);
});

it("keeps channel selection independent and releases a failed request for retry", async () => {
  const stable = deferred();
  const live = deferred();
  h.invoke.mockImplementation((_command, { channel }) =>
    channel === "Stable" ? stable.promise : live.promise);
  const failed = Promise.allSettled([
    updaterCheckChannel("Stable"), updaterCheckChannel("Stable"),
  ]);
  const other = updaterCheckChannel("Live");
  const requests = h.invoke.mock.calls.map(call => call[1].channel);
  stable.reject(new Error("fixture unavailable"));
  live.resolve({ ...result, channel: "Live" });
  expect((await failed).every(outcome => outcome.status === "rejected")).toBe(true);
  expect(await other).toMatchObject({ channel: "Live" });
  expect(requests).toEqual(["Stable", "Live"]);
  h.invoke.mockResolvedValue(result);
  await updaterCheckChannel("Stable");
  expect(h.invoke).toHaveBeenCalledTimes(3);
});
