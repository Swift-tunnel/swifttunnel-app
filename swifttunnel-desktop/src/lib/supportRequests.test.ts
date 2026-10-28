import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
import { settingsGenerateNetworkDiagnosticsBundle, systemCopyLogToClipboard } from "./commands";
const copied = { file_path: "fixture.log" };
const report = { file_path: "fixture.txt", folder_path: "fixture-folder" };
beforeEach(() => h.invoke.mockReset());

it("shares a pending report through Repair and Settings but creates a fresh report later", async () => {
  let finish!: (value: typeof report) => void;
  h.invoke.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const first = settingsGenerateNetworkDiagnosticsBundle();
  const second = settingsGenerateNetworkDiagnosticsBundle();
  const count = h.invoke.mock.calls.length;
  finish(report); await Promise.all([first, second]);
  expect(count).toBe(1);
  h.invoke.mockResolvedValue(report);
  await settingsGenerateNetworkDiagnosticsBundle();
  expect(h.invoke).toHaveBeenCalledTimes(2);
});

it("shares pending log copies without blocking a separate report", async () => {
  let finish!: (value: typeof copied) => void;
  const copying = new Promise(resolve => { finish = resolve; });
  h.invoke.mockImplementation((command: string) => command === "system_copy_log_to_clipboard"
    ? copying : Promise.resolve(report));
  const first = systemCopyLogToClipboard(), second = systemCopyLogToClipboard();
  await settingsGenerateNetworkDiagnosticsBundle();
  const copies = h.invoke.mock.calls.filter(([command]) => command === "system_copy_log_to_clipboard").length;
  finish(copied); await Promise.all([first, second]);
  expect(copies).toBe(1);
});

it("releases failed support work so each action can retry", async () => {
  h.invoke.mockRejectedValueOnce(new Error("report unavailable")).mockResolvedValueOnce(report)
    .mockRejectedValueOnce(new Error("clipboard busy")).mockResolvedValueOnce(copied);
  await expect(settingsGenerateNetworkDiagnosticsBundle()).rejects.toThrow("report unavailable");
  await expect(settingsGenerateNetworkDiagnosticsBundle()).resolves.toEqual(report);
  await expect(systemCopyLogToClipboard()).rejects.toThrow("clipboard busy");
  await expect(systemCopyLogToClipboard()).resolves.toEqual(copied);
});
