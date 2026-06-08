import { create } from "zustand";
import type { OptimizationDef } from "../components/optimization/optimizationCatalog";
import { useToastStore } from "./toastStore";
import { notify } from "../lib/notifications";
import {
  optimizationApply,
  optimizationRevert,
  optimizationGetActive,
} from "../lib/commands";
import { reportError } from "../lib/errors";

export type OptStatus = "inactive" | "activating" | "active" | "deactivating";

interface OptimizationStore {
  status: Record<string, OptStatus>;
  loaded: boolean;
  loadActive: () => Promise<void>;
  activate: (def: OptimizationDef) => Promise<void>;
  deactivate: (def: OptimizationDef) => Promise<void>;
}

export const useOptimizationStore = create<OptimizationStore>((set, get) => ({
  status: {},
  loaded: false,

  /** Load which optimizations are currently applied (persisted snapshots). */
  loadActive: async () => {
    try {
      const active = await optimizationGetActive();
      const status: Record<string, OptStatus> = {};
      for (const id of active) status[id] = "active";
      set({ status, loaded: true });
    } catch (error) {
      reportError("Failed to load optimization states", error, {
        dedupeKey: "optimization-load",
      });
      set({ loaded: true });
    }
  },

  activate: async (def) => {
    if (get().status[def.id] === "active") return;
    set((s) => ({ status: { ...s.status, [def.id]: "activating" } }));

    try {
      const res = await optimizationApply(def.id);
      // A defined response proves the real backend command ran. If it's
      // undefined the command wasn't available (e.g. a stale dev build), so we
      // must NOT pretend it succeeded.
      if (!res || typeof res.requires_reboot !== "boolean") {
        throw new Error(
          "Optimization backend unavailable — fully restart SwiftTunnel and try again.",
        );
      }

      set((s) => ({ status: { ...s.status, [def.id]: "active" } }));
      useToastStore.getState().addToast({
        type: "success",
        message: `${def.name} activated`,
      });

      // Restart-required tweaks surface through SwiftTunnel's normal
      // notification channels (in-app toast + OS notification).
      if (res.requires_reboot) {
        useToastStore.getState().addToast({
          type: "warning",
          message: `Restart your PC to finish applying ${def.name}.`,
        });
        void notify(
          "Restart required",
          `Restart your PC to finish applying ${def.name}.`,
        );
      }
    } catch (error) {
      set((s) => ({ status: { ...s.status, [def.id]: "inactive" } }));
      useToastStore.getState().addToast({
        type: "error",
        message: `Couldn't activate ${def.name}: ${String(error)}`,
      });
    }
  },

  deactivate: async (def) => {
    const current = get().status[def.id];
    if (current !== "active" && current !== "activating") return;
    set((s) => ({ status: { ...s.status, [def.id]: "deactivating" } }));

    try {
      const res = await optimizationRevert(def.id);
      if (!res || typeof res.requires_reboot !== "boolean") {
        throw new Error(
          "Optimization backend unavailable — fully restart SwiftTunnel and try again.",
        );
      }

      set((s) => ({ status: { ...s.status, [def.id]: "inactive" } }));
      useToastStore.getState().addToast({
        type: "info",
        message: `${def.name} reverted`,
      });

      if (res.requires_reboot) {
        void notify(
          "Restart required",
          `Restart your PC to finish reverting ${def.name}.`,
        );
      }
    } catch (error) {
      set((s) => ({ status: { ...s.status, [def.id]: "active" } }));
      useToastStore.getState().addToast({
        type: "error",
        message: `Couldn't revert ${def.name}: ${String(error)}`,
      });
    }
  },
}));
