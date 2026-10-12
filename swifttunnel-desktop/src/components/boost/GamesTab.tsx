import { useEffect, useState } from "react";
import { Icon } from "../ui";
import { GameLibraryPanel } from "./LauncherLibrary";
import { GameToolsPanel } from "./GameToolsPanel";
import { BoostTab } from "./BoostTab";
import { FastFlagsPanel } from "./FastFlagsPanel";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import type { RobloxSettingsConfig } from "../../lib/types";

const SECTIONS = [
  { id: "library", label: "Library", icon: "games" },
  { id: "settings", label: "Roblox settings", icon: "roblox" },
  { id: "flags", label: "FastFlags", icon: "settings" },
] as const;

export function GamesTab() {
  const [view, setView] = useState<"library" | "settings" | "flags">("library");
  const [flagsVisited, setFlagsVisited] = useState(false);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [imported, setImported] = useState<Partial<RobloxSettingsConfig> | null>(null);
  const anchor = useDeepLinkStore(s => s.anchor);
  useEffect(() => {
    if (!anchor) return;
    if (anchor === "custom_fflags" || anchor === "flags_advanced" || anchor.startsWith("flag_") || anchor.startsWith("nvidia_")) { setView("flags"); setFlagsVisited(true); }
    else if (anchor.startsWith("games_") || anchor === "join_notifications") setView("library");
    else { setView("settings"); if (anchor === "roblox_maintenance") setToolsOpen(true); }
  }, [anchor]);

  return <div className="flex flex-col gap-4 pb-12">
    {/* The same switcher as Optimize. The window's top bar already names the
        page and shows the connection, so nothing else sits above the games. */}
    <nav
      aria-label="Games sections"
      className="flex w-fit items-center gap-1 rounded-[10px] p-1"
      style={{ backgroundColor: "var(--color-bg-card)", border: "1px solid var(--color-border-subtle)" }}
    >
      {SECTIONS.map(item => (
        <button
          key={item.id}
          type="button"
          onClick={() => { setView(item.id); if (item.id === "flags") setFlagsVisited(true); }}
          aria-current={view === item.id ? "page" : undefined}
          className="flex items-center gap-2 rounded-[7px] px-4 py-1.5 text-[12px] font-medium transition-colors"
          style={{
            backgroundColor: view === item.id ? "var(--color-bg-active)" : "transparent",
            color: view === item.id ? "var(--color-text-primary)" : "var(--color-text-muted)",
          }}
        >
          <Icon name={item.icon} size={14} />
          {item.label}
        </button>
      ))}
    </nav>

    {view === "library" && <GameLibraryPanel />}
    {view === "settings" && <div className="flex flex-col gap-4">
      <BoostTab importPatch={imported} onImportConsumed={() => setImported(null)} />
      {/* Collapsed like Repair's "Last repair", so occasional maintenance stays out of the way. */}
      <section data-search-anchor="roblox_maintenance" className="instrument">
        <button type="button" aria-expanded={toolsOpen} onClick={() => setToolsOpen(open => !open)} className="flex w-full items-center justify-between gap-3 px-3.5 py-3 text-left">
          <span className="flex items-center gap-2">
            <Icon name="chevron-right" size={12} strokeWidth={2.2} style={{ color: "var(--color-text-muted)", transform: toolsOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s ease" }} />
            <span className="eyebrow">Maintenance & existing launcher settings</span>
          </span>
          <span className="font-mono text-[10.5px] text-text-dimmed">Import · clean up · undo</span>
        </button>
        {/* Kept mounted while closed, as the old <details> did, so a half-reviewed import survives collapsing it. */}
        <div hidden={!toolsOpen} className="border-t border-border-subtle"><GameToolsPanel disabled={false} onImport={patch => { setImported(patch); }} /></div>
      </section>
    </div>}
    {flagsVisited && <div hidden={view !== "flags"}><FastFlagsPanel /></div>}
  </div>;
}
