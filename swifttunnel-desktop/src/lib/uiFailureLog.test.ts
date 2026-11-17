import { expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { reportUiFailure } from "./uiFailureLog";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

it("sends only the surface and safe error category to the support log", () => {
  vi.mocked(invoke).mockResolvedValue(undefined);
  reportUiFailure("games", new TypeError("private login URL and local file path"));
  expect(invoke).toHaveBeenCalledWith("system_record_ui_failure", {
    page: "games",
    kind: "type_error",
  });
});
