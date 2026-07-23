import { create } from "zustand";
import { useToastStore } from "./toastStore";
import { notify } from "../lib/notifications";
import {
  optimizationApply,
  optimizationRevert,
  optimizationGetActive,
} from "../lib/commands";
import { reportError } from "../lib/errors";

export type OptStatus = "inactive" | "activating" | "active" | "deactivating";

/** Anything with an id + display name can be toggled (catalog or Speed Up). */
type OptTarget = { id: string; name: string };

/** Per-item result so bulk callers can aggregate into one summary toast. */
export interface OptOutcome {
  ok: boolean;
  requiresReboot: boolean;
}

/** silent: no per-item toasts/notifications — bulk callers summarize instead. */
type OptOptions = { silent?: boolean };

interface OptimizationStore {
  status: Record<string, OptStatus>;
  loaded: boolean;
  loadActive: () => Promise<void>;
  activate: (def: OptTarget, opts?: OptOptions) => Promise<OptOutcome>;
  deactivate: (def: OptTarget, opts?: OptOptions) => Promise<OptOutcome>;
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

  activate: async (def, opts) => {
    if (get().status[def.id] === "active") {
      return { ok: true, requiresReboot: false };
    }
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
      if (!opts?.silent) {
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
      }
      return { ok: true, requiresReboot: res.requires_reboot };
    } catch (error) {
      set((s) => ({ status: { ...s.status, [def.id]: "inactive" } }));
      if (!opts?.silent) {
        useToastStore.getState().addToast({
          type: "error",
          message: `Couldn't activate ${def.name}: ${String(error)}`,
        });
      }
      return { ok: false, requiresReboot: false };
    }
  },

  deactivate: async (def, opts) => {
    const current = get().status[def.id];
    if (current !== "active" && current !== "activating") {
      return { ok: true, requiresReboot: false };
    }
    set((s) => ({ status: { ...s.status, [def.id]: "deactivating" } }));

    try {
      const res = await optimizationRevert(def.id);
      if (!res || typeof res.requires_reboot !== "boolean") {
        throw new Error(
          "Optimization backend unavailable — fully restart SwiftTunnel and try again.",
        );
      }

      set((s) => ({ status: { ...s.status, [def.id]: "inactive" } }));
      if (!opts?.silent) {
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
      }
      return { ok: true, requiresReboot: res.requires_reboot };
    } catch (error) {
      set((s) => ({ status: { ...s.status, [def.id]: "active" } }));
      if (!opts?.silent) {
        useToastStore.getState().addToast({
          type: "error",
          message: `Couldn't revert ${def.name}: ${String(error)}`,
        });
      }
      return { ok: false, requiresReboot: false };
    }
  },
}));
