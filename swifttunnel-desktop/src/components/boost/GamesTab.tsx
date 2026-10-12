import { useState } from "react";
import { Icon } from "../ui";
import { GameLibraryPanel } from "./LauncherLibrary";
import { GameToolsPanel } from "./GameToolsPanel";
import { BoostTab } from "./BoostTab";
import { useVpnStore } from "../../stores/vpnStore";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import type { RobloxSettingsConfig } from "../../lib/types";

export function GamesTab() {
  const [view, setView] = useState<"library" | "settings" | "tools">("library");
  const [imported, setImported] = useState<Partial<RobloxSettingsConfig> | null>(null);
  const tunnel = useVpnStore(s => s.state);
  const count = useGameLibraryStore(s => s.library?.entries.length ?? 0);
  return <div className="space-y-5 pb-12">
    <header className="relative flex items-center justify-between gap-4 overflow-hidden rounded-2xl border border-border-subtle px-5 py-5" style={{ background: "linear-gradient(115deg,var(--color-bg-elevated),var(--color-accent-primary-soft-8))" }}>
      <div className="flex items-center gap-4"><div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-border-subtle bg-bg-base"><Icon name="roblox" size={24} className="text-text-primary" /></div><div><h1 className="text-xl font-semibold tracking-tight text-text-primary">Your games.</h1><p className="mt-1 text-xs text-text-muted">A quick launch. A route you control.</p></div></div>
      <div className="text-right"><p className="text-[11px] font-medium text-text-secondary">{tunnel === "connected" ? "SwiftTunnel connected" : "SwiftTunnel disconnected"}</p><p className="mt-1 text-[10px] text-text-muted">{count} saved {count === 1 ? "game" : "games"}</p></div>
    </header>
    <nav aria-label="Games sections" className="flex gap-1 border-b border-border-subtle">
      {([{ id: "library", label: "Library", icon: "games" }, { id: "settings", label: "Roblox settings", icon: "settings" }, { id: "tools", label: "Tools & imports", icon: "repair" }] as const).map(item => <button key={item.id} onClick={() => setView(item.id)} aria-current={view === item.id ? "page" : undefined}
        className={`relative flex items-center gap-2 px-4 pb-3 pt-2 text-xs transition-colors ${view === item.id ? "font-semibold text-text-primary" : "text-text-muted hover:text-text-secondary"}`}>
        <Icon name={item.icon} size={14} />{item.label}{view === item.id && <span className="absolute inset-x-3 bottom-[-1px] h-[2px] rounded-full bg-text-primary" />}
      </button>)}
    </nav>
    {view === "library" && <GameLibraryPanel />}
    {view === "settings" && <BoostTab importPatch={imported} onImportConsumed={() => setImported(null)} />}
    {view === "tools" && <GameToolsPanel disabled={false} onImport={patch => { setImported(patch); setView("settings"); }} />}
  </div>;
}
