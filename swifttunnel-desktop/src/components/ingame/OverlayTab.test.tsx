import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { OverlayTab } from "./OverlayTab";
import { navItemFor } from "../shell/nav";
describe("Overlay settings", () => {
  it("renames the visible tab while keeping saved navigation compatible", () => {
    expect(navItemFor("ingame").label).toBe("Overlay");
    const html = renderToStaticMarkup(<OverlayTab />);
    expect(html).toContain("SAMPLE VALUES");
    expect(html).toContain("Lock overlay position");
    expect(html).toContain("Game ping");
    expect(html).not.toContain("session chart");
    expect(html).not.toContain("anti-cheat safe");
    expect(html).not.toContain("CPU Temp");
    expect(html).not.toContain("Auto-clean RAM");
  });
});
