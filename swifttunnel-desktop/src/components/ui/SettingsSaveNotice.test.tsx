import { beforeEach, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

const h = vi.hoisted(() => ({
  loadError: null as string | null,
  saveError: null as string | null,
  saveWarning: null as string | null,
  save: vi.fn(),
}));
vi.mock("../../stores/settingsStore", () => ({
  useSettingsStore: (select: (state: typeof h) => unknown) => select(h),
}));
import { SettingsSaveNotice } from "./SettingsSaveNotice";

beforeEach(() => { h.loadError = null; h.saveError = null; h.saveWarning = null; });

it("explains a load failure without offering to save startup defaults over it", () => {
  h.loadError = "Restart SwiftTunnel to reload your saved settings before saving changes.";
  h.saveError = "Previous save failure";
  const html = renderToStaticMarkup(<SettingsSaveNotice />);
  expect(html).toContain("Your saved settings could not be loaded.");
  expect(html).toContain(h.loadError);
  expect(html).not.toContain("Retry saving");
  expect(html).not.toContain("Previous save failure");
});

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
