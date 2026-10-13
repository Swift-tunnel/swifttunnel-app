import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LauncherImportPanel } from "./LauncherImportPanel";

describe("launcher import in Settings", () => {
  it("starts as an off toggle without bringing back maintenance or profile controls", () => {
    const html = renderToStaticMarkup(<LauncherImportPanel />);
    expect(html).toContain('data-search-anchor="launcher_import"');
    expect(html).toContain('aria-label="Import launcher settings"');
    expect(html).toContain('aria-checked="false"');
    expect(html).not.toContain("Settings profiles");
    expect(html).not.toContain("Clean old logs");
    expect(html).not.toContain("Maintenance");
  });
});
