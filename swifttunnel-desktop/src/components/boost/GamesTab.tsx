import { useEffect, useState } from "react";
import { Icon } from "../ui";
import { GameLibraryPanel } from "./LauncherLibrary";
import { BoostTab } from "./BoostTab";
import { FastFlagsPanel } from "./FastFlagsPanel";
import { MatchmakerPanel } from "./MatchmakerPanel";
import { useDeepLinkStore } from "../../stores/deepLinkStore";

const SECTIONS = [
  { id: "library", label: "Library", icon: "games" },
  { id: "matchmaker", label: "Matchmaker", icon: "globe" },
  { id: "settings", label: "Roblox settings", icon: "roblox" },
  { id: "flags", label: "FastFlags", icon: "settings" },
] as const;

export function GamesTab() {
  const [view, setView] = useState<"library" | "matchmaker" | "settings" | "flags">("library");
  const [flagsVisited, setFlagsVisited] = useState(false);
  const anchor = useDeepLinkStore(s => s.anchor);
  useEffect(() => {
    if (!anchor) return;
    if (anchor === "custom_fflags" || anchor === "flags_advanced" || anchor.startsWith("flag_") || anchor.startsWith("nvidia_")) { setView("flags"); setFlagsVisited(true); }
    else if (anchor === "matchmaker") setView("matchmaker");
    else if (anchor.startsWith("games_") || anchor === "join_notifications") setView("library");
    else setView("settings");
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
    {view === "matchmaker" && <MatchmakerPanel />}
    {view === "settings" && <BoostTab />}
    {flagsVisited && <div hidden={view !== "flags"}><FastFlagsPanel /></div>}
  </div>;
}
