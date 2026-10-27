import { beforeEach, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

const h = vi.hoisted(() => ({
  saveError: null as string | null,
  saveWarning: null as string | null,
  save: vi.fn(),
}));
vi.mock("../../stores/settingsStore", () => ({
  useSettingsStore: (select: (state: typeof h) => unknown) => select(h),
}));
import { SettingsSaveNotice } from "./SettingsSaveNotice";

beforeEach(() => { h.saveError = null; h.saveWarning = null; });

it("offers a startup retry without calling a saved preference a failed save", () => {
  h.saveWarning = "Your settings were saved, but Windows startup could not be updated.";
  const html = renderToStaticMarkup(<SettingsSaveNotice />);
  expect(html).toContain(h.saveWarning);
  expect(html).toContain("Retry startup setup");
  expect(html).not.toContain("Settings could not be saved:");
});

it("prioritizes an unsaved settings failure while keeping its retry available", () => {
  h.saveWarning = "Startup setup warning";
  h.saveError = "Disk full";
  const html = renderToStaticMarkup(<SettingsSaveNotice />);
  expect(html).toContain("Disk full");
  expect(html).toContain("Retry saving");
  expect(html).not.toContain(h.saveWarning);
});

it("shows no notice after a clean save", () => {
  expect(renderToStaticMarkup(<SettingsSaveNotice />)).toBe("");
});
