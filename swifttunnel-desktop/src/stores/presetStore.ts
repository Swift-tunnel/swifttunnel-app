// Local library of saved presets you can switch between like config loadouts.
//
// A preset is the shareable snapshot from lib/presets (everything except
// tunneling) plus a local `id`. The list + which one is active persist in
// localStorage. Applying ("switching to") a preset merges its config over the
// current one and re-applies its optimization catalog items.

import { create } from "zustand";
import { useToastStore } from "./toastStore";
import { useSettingsStore } from "./settingsStore";
import { useBoostStore } from "./boostStore";
import { useOptimizationStore } from "./optimizationStore";
import { formatErrorMessage } from "../lib/errors";
import {
  buildPreset,
  decodePreset,
  mergePresetIntoConfig,
  type SwiftTunnelPreset,
} from "../lib/presets";
import {
  OPTIMIZATIONS,
  SPEEDUP_OPTIMIZATIONS,
} from "../components/optimization/optimizationCatalog";

export interface SavedPreset extends SwiftTunnelPreset {
  id: string;
}

const LIST_KEY = "st.presetLibrary";
const ACTIVE_KEY = "st.activePresetId";

const CATALOG_BY_ID = new Map<string, { id: string; name: string }>();
for (const o of [...OPTIMIZATIONS, ...SPEEDUP_OPTIMIZATIONS]) {
  CATALOG_BY_ID.set(o.id, { id: o.id, name: o.name });
}

function loadList(): SavedPreset[] {
  try {
    const v = JSON.parse(localStorage.getItem(LIST_KEY) || "[]");
    if (!Array.isArray(v)) return [];
    const ids = new Set<string>();
    const valid: SavedPreset[] = [];
    for (const item of v) {
      if (!item || typeof item.id !== "string" || !item.id.trim() || ids.has(item.id)) continue;
      try {
        // Stored data can be incomplete or from an older version. Apply the
        // same shape/range checks as imports before rendering or merging it.
        const preset = decodePreset(JSON.stringify(item));
        valid.push({ ...preset, id: item.id });
        ids.add(item.id);
      } catch {
        // Keep other valid entries usable. Do not rewrite storage on load.
      }
    }
    return valid;
  } catch {
    return [];
  }
}
function persistList(list: SavedPreset[]) {
  try {
    localStorage.setItem(LIST_KEY, JSON.stringify(list));
  } catch {
    /* best-effort */
  }
}
function loadActive(): string | null {
  try {
    return localStorage.getItem(ACTIVE_KEY);
  } catch {
    return null;
  }
}
function persistActive(id: string | null) {
  try {
    if (id) localStorage.setItem(ACTIVE_KEY, id);
    else localStorage.removeItem(ACTIVE_KEY);
  } catch {
    /* best-effort */
  }
}

function newId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `p_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  }
}

function activeOptimizationIds(): string[] {
  const status = useOptimizationStore.getState().status;
  return Object.keys(status).filter((id) => status[id] === "active");
}

interface PresetStore {
  presets: SavedPreset[];
  activeId: string | null;
  applyingId: string | null;

  /** Save the current setup as a new named preset (and mark it active). */
  createFromCurrent: (name: string) => SavedPreset;
  /** Add an imported/decoded preset to the library. */
  addImported: (preset: SwiftTunnelPreset) => SavedPreset;
  remove: (id: string) => void;
  /** Switch to a preset: apply its config + optimizations. */
  apply: (id: string) => Promise<void>;
}

const initialPresets = loadList();
const initialActiveId = loadActive();

export const usePresetStore = create<PresetStore>((set, get) => ({
  presets: initialPresets,
  activeId: initialPresets.some((preset) => preset.id === initialActiveId) ? initialActiveId : null,
  applyingId: null,

  createFromCurrent: (name) => {
    const settings = useSettingsStore.getState().settings;
    const base = buildPreset(name, settings, activeOptimizationIds());
    const preset: SavedPreset = { ...base, id: newId() };
    const presets = [preset, ...get().presets];
    persistList(presets);
    persistActive(preset.id);
    set({ presets, activeId: preset.id });
    return preset;
  },

  addImported: (base) => {
    const preset: SavedPreset = { ...base, id: newId() };
    const presets = [preset, ...get().presets];
    persistList(presets);
    set({ presets });
    return preset;
  },

  remove: (id) => {
    const presets = get().presets.filter((p) => p.id !== id);
    const activeId = get().activeId === id ? null : get().activeId;
    persistList(presets);
    persistActive(activeId);
    set({ presets, activeId });
  },

  apply: async (id) => {
    const preset = get().presets.find((p) => p.id === id);
    if (!preset || get().applyingId) return;
    set({ applyingId: id });
    const addToast = useToastStore.getState().addToast;
    try {
      // Applying can change some settings before failing. Neither the old
      // nor the requested preset describes that partial state reliably.
      persistActive(null);
      set({ activeId: null });
      // 1) Settings (Roblox, overlay, network, portable system tweaks).
      const cur = useSettingsStore.getState().settings;
      const nextConfig = mergePresetIntoConfig(cur.config, preset);
      const applied = await useBoostStore
        .getState()
        .updateConfig(JSON.stringify(nextConfig));
      useSettingsStore.getState().update({
        config: applied,
        selected_game_presets: preset.game_presets,
      });
      await useSettingsStore.getState().save(true);

      // 2) Optimization catalog items, apply each known id, aggregate.
      const activate = useOptimizationStore.getState().activate;
      const targets = preset.optimizations
        .map((oid) => CATALOG_BY_ID.get(oid))
        .filter((t): t is { id: string; name: string } => Boolean(t));
      let ok = 0;
      let failed = preset.optimizations.filter((oid) => !CATALOG_BY_ID.has(oid)).length;
      let reboot = false;
      for (const t of targets) {
        const r = await activate(t, { silent: true });
        if (r.ok) ok++;
        else failed++;
        if (r.requiresReboot) reboot = true;
      }

      const warning = useBoostStore.getState().warning;
      if (failed || warning) {
        addToast({
          type: "warning",
          message: `"${preset.name}" only partially applied. ${failed ? `${failed} optimization${failed === 1 ? "" : "s"} failed or are unavailable. ` : ""}${warning ? `${warning} ` : ""}Review the settings before retrying.${reboot ? " Restart your PC to finish completed changes." : ""}`,
        });
        return;
      }
      persistActive(id);
      set({ activeId: id });
      // Roblox reads its settings files at launch, changes applied while the
      // client is open only take effect after a restart.
      const robloxOpen = useBoostStore.getState().robloxRunning;
      addToast({
        type: "success",
        message: `Switched to "${preset.name}"${
          ok ? `, ${ok} optimization${ok === 1 ? "" : "s"} on` : ""
        }.${reboot ? " Restart your PC to finish some." : ""}${
          robloxOpen ? " Restart Roblox to apply its settings." : ""
        }`,
      });
    } catch (e) {
      addToast({ type: "error", message: `Couldn't finish switching preset: ${formatErrorMessage(e)}. Some settings may have changed. Review them before retrying.` });
    } finally {
      set({ applyingId: null });
    }
  },
}));
