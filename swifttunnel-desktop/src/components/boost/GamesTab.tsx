import { useEffect, useState } from "react";
import { Icon, Panel } from "../ui";
import { GameLibraryPanel } from "./LauncherLibrary";
import { GameToolsPanel } from "./GameToolsPanel";
import { BoostTab } from "./BoostTab";
import { FastFlagsPanel } from "./FastFlagsPanel";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import type { RobloxSettingsConfig } from "../../lib/types";

export function GamesTab() {
  const [view, setView] = useState<"library" | "settings" | "flags">("library");
  const [flagsVisited, setFlagsVisited] = useState(false);
  const [imported, setImported] = useState<Partial<RobloxSettingsConfig> | null>(null);
  const tunnel = useVpnStore(s => s.state);
  const count = useGameLibraryStore(s => s.library?.entries.length ?? 0);
  const anchor = useDeepLinkStore(s => s.anchor);
  useEffect(() => {
    if (!anchor) return;
    if (anchor === "custom_fflags") { setView("flags"); setFlagsVisited(true); }
    else setView("settings");
  }, [anchor]);
  return <div className="space-y-5 pb-12">
    <Panel eyebrow="Roblox workspace" title={<span className="text-xl tracking-tight">{view === "flags" ? "FastFlags." : view === "settings" ? "Roblox settings." : "Your games."}</span>} desc={view === "flags" ? "Your Roblox engine overrides and NVIDIA driver profile." : view === "settings" ? "Performance and launch preferences, with changes you control." : "Your library, engine settings and connection in one place."} watermark={{icon:"roblox",at:"right",size:180,rotate:-14,fade:true,opacity:.055}}
      actions={<div className="text-right"><p className="flex items-center justify-end gap-1.5 text-[11px] font-medium text-text-secondary"><span className={`h-1.5 w-1.5 rounded-full ${tunnel === "connected" ? "bg-status-connected" : "bg-text-dimmed"}`} />{tunnel === "connected" ? "Connected" : "Disconnected"}</p><p className="mt-1 text-[10px] text-text-muted">{count} saved {count === 1 ? "game" : "games"}</p></div>} />
    <nav aria-label="Games sections" className="flex gap-1 border-b border-border-subtle">
      {([{ id: "library", label: "Library", icon: "games" }, { id: "settings", label: "Roblox settings", icon: "roblox" }, { id: "flags", label: "FastFlags", icon: "settings" }] as const).map(item => <button key={item.id} onClick={() => {setView(item.id);if(item.id==="flags")setFlagsVisited(true);}} aria-current={view === item.id ? "page" : undefined}
        className={`relative flex items-center gap-2 px-4 pb-3 pt-2 text-xs transition-colors ${view === item.id ? "font-semibold text-text-primary" : "text-text-muted hover:text-text-secondary"}`}>
        <Icon name={item.icon} size={14} />{item.label}{view === item.id && <span className="absolute inset-x-3 bottom-[-1px] h-[2px] rounded-full bg-text-primary" />}
      </button>)}
    </nav>
    {view === "library" && <GameLibraryPanel />}
    {view === "settings" && <div className="space-y-5"><BoostTab importPatch={imported} onImportConsumed={() => setImported(null)} /><details className="instrument p-4"><summary className="cursor-pointer text-xs font-medium text-text-secondary">Maintenance & existing launcher settings</summary><div className="mt-4"><GameToolsPanel disabled={false} onImport={patch => { setImported(patch); }} /></div></details></div>}
    {flagsVisited && <div hidden={view !== "flags"}><FastFlagsPanel /></div>}
  </div>;
}
