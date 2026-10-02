import { create } from "zustand";
import { useToastStore } from "./toastStore";
import { notify } from "../lib/notifications";
import {
  optimizationApply,
  optimizationRevert,
  optimizationGetActive,
} from "../lib/commands";
import { formatErrorMessage, reportError } from "../lib/errors";

export type OptStatus = "inactive" | "activating" | "active" | "deactivating";

/** Anything with an id + display name can be toggled (catalog or Speed Up). */
type OptTarget = { id: string; name: string };

/** Per-item result so bulk callers can aggregate into one summary toast. */
export interface OptOutcome {
  ok: boolean;
  requiresReboot: boolean;
}

/** silent: no per-item toasts/notifications, bulk callers summarize instead. */
type OptOptions = { silent?: boolean; batchToken?: symbol };

export interface OptBatchResult {
  changed: number;
  failed: number;
  reboot: number;
}

interface OptimizationStore {
  status: Record<string, OptStatus>;
  loaded: boolean;
  loading: boolean;
  loadError: string | null;
  errors: Record<string, string>;
  restartRequired: boolean;
  batch: { action: "apply" | "revert"; completed: number; total: number } | null;
  runBatch: (targets: OptTarget[], action: "apply" | "revert", prepare?: () => Promise<void>) => Promise<OptBatchResult | null>;
  loadActive: () => Promise<void>;
  activate: (def: OptTarget, opts?: OptOptions) => Promise<OptOutcome>;
  deactivate: (def: OptTarget, opts?: OptOptions) => Promise<OptOutcome>;
}

function isBusy(status: OptStatus | undefined): boolean {
  return status === "activating" || status === "deactivating";
}

function busyOutcome(def: OptTarget, opts?: OptOptions): OptOutcome {
  if (!opts?.silent) {
    useToastStore.getState().addToast({
      type: "warning",
      message: `${def.name} is still changing. Wait for it to finish.`,
    });
  }
  return { ok: false, requiresReboot: false };
}

export const useOptimizationStore = create<OptimizationStore>((set, get) => {
  const revisions = new Map<string, number>();
  let loadRequest = 0;
  let batchOwner: symbol | null = null;
  const blockedByBatch = (opts?: OptOptions) => batchOwner !== null && opts?.batchToken !== batchOwner;
  const setStatus = (id: string, status: OptStatus) => {
    // Count both start and completion, including an action already in flight
    // when a status read begins. Preserve unrelated items from that read.
    revisions.set(id, (revisions.get(id) ?? 0) + 1);
    set((s) => ({ status: { ...s.status, [id]: status } }));
  };
  return {
    status: {},
    loaded: false,
    loading: false,
    loadError: null,
    errors: {},
    restartRequired: false,
    batch: null,

    runBatch: async (targets, action, prepare) => {
      if (batchOwner || !get().loaded || Object.values(get().status).some(isBusy)) return null;
      // Snapshot and deduplicate the work before the first await. A second
      // control or a remounted tab must not start an opposing batch.
      const unique = [...new Map(targets.map((target) => [target.id, target])).values()];
      const pending = unique.filter((target) => action === "apply"
        ? get().status[target.id] !== "active"
        : get().status[target.id] === "active");
      const token = Symbol("optimization batch");
      batchOwner = token;
      set({ batch: { action, completed: 0, total: pending.length } });
      const result: OptBatchResult = { changed: 0, failed: 0, reboot: 0 };
      try {
        // Preset settings must share the same lock as their catalog changes.
        // Do not mutate config first and only discover a conflicting batch later.
        await prepare?.();
        for (const target of pending) {
          const outcome = await (action === "apply" ? get().activate : get().deactivate)(target, { silent: true, batchToken: token });
          if (!outcome.ok) result.failed += 1;
          else {
            result.changed += 1;
            if (outcome.requiresReboot) result.reboot += 1;
          }
          set({ batch: { action, completed: result.changed + result.failed, total: pending.length } });
        }
        return result;
      } finally {
        batchOwner = null;
        set({ batch: null });
      }
    },

    /** Load which optimizations are currently applied (persisted snapshots). */
    loadActive: async () => {
      const request = ++loadRequest;
      const before = new Map(revisions);
      set({ loading: true, loadError: null });
      try {
        const active = await optimizationGetActive();
        if (request !== loadRequest) return;
        if (!Array.isArray(active) || active.some((id) => typeof id !== "string")) {
          throw new Error("Optimization status is unavailable. Retry before changing tweaks.");
        }
        const status: Record<string, OptStatus> = {};
        for (const id of active) status[id] = "active";
        for (const [id, current] of Object.entries(get().status)) {
          if (isBusy(current) || revisions.get(id) !== before.get(id)) {
            status[id] = current;
          }
        }
        set({ status, loaded: true, loading: false });
      } catch (error) {
        if (request !== loadRequest) return;
        reportError("Failed to load optimization states", error, {
          dedupeKey: "optimization-load",
        });
        set({ loaded: false, loading: false, loadError: formatErrorMessage(error) });
      }
    },

    activate: async (def, opts) => {
      if (blockedByBatch(opts)) return busyOutcome({ ...def, name: "An optimization batch" }, opts);
      if (isBusy(get().status[def.id])) return busyOutcome(def, opts);
      if (get().status[def.id] === "active") {
        return { ok: true, requiresReboot: false };
      }
      setStatus(def.id, "activating");
      set((s) => ({ errors: { ...s.errors, [def.id]: "" } }));

      try {
        const res = await optimizationApply(def.id);
        // A defined response proves the real backend command ran. If it's
        // undefined the command wasn't available (e.g. a stale dev build), so we
        // must NOT pretend it succeeded.
        if (!res || typeof res.requires_reboot !== "boolean") {
          throw new Error(
            "Optimization backend unavailable, fully restart SwiftTunnel and try again.",
          );
        }

        setStatus(def.id, "active");
        if (res.requires_reboot) set({ restartRequired: true });
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
        // A failed apply can leave a durable rollback record. Keep Revert
        // available for recovery instead of hiding it as an inactive tweak.
        let needsRevert = false;
        try {
          needsRevert = (await optimizationGetActive()).includes(def.id);
        } catch {
          // The original failure remains visible, including its recovery step.
        }
        setStatus(def.id, needsRevert ? "active" : "inactive");
        const message = formatErrorMessage(error);
        set((s) => ({ errors: { ...s.errors, [def.id]: message } }));
        if (!opts?.silent) {
          useToastStore.getState().addToast({
            type: "error",
            message: `Couldn't activate ${def.name}: ${message}`,
          });
        }
        return { ok: false, requiresReboot: false };
      }
    },

    deactivate: async (def, opts) => {
      if (blockedByBatch(opts)) return busyOutcome({ ...def, name: "An optimization batch" }, opts);
      const current = get().status[def.id];
      if (isBusy(current)) return busyOutcome(def, opts);
      if (current !== "active") {
        return { ok: true, requiresReboot: false };
      }
      setStatus(def.id, "deactivating");
      set((s) => ({ errors: { ...s.errors, [def.id]: "" } }));

      try {
        const res = await optimizationRevert(def.id);
        if (!res || typeof res.requires_reboot !== "boolean") {
          throw new Error(
            "Optimization backend unavailable, fully restart SwiftTunnel and try again.",
          );
        }

        setStatus(def.id, "inactive");
        if (res.requires_reboot) set({ restartRequired: true });
        if (!opts?.silent) {
          useToastStore.getState().addToast({
            type: "info",
            message: `${def.name} reverted`,
          });

          if (res.requires_reboot) {
            // Toast as well as the OS notification, matching the apply path. A
            // revert only half-takes-effect the same way an apply does, so
            // someone who turned a tweak off and saw nothing change would
            // reasonably conclude the revert had failed.
            useToastStore.getState().addToast({
              type: "warning",
              message: `Restart your PC to finish reverting ${def.name}.`,
            });
            void notify(
              "Restart required",
              `Restart your PC to finish reverting ${def.name}.`,
            );
          }
        }
        return { ok: true, requiresReboot: res.requires_reboot };
      } catch (error) {
        setStatus(def.id, "active");
        const message = formatErrorMessage(error);
        set((s) => ({ errors: { ...s.errors, [def.id]: message } }));
        if (!opts?.silent) {
          useToastStore.getState().addToast({
            type: "error",
            message: `Couldn't revert ${def.name}: ${message}`,
          });
        }
        return { ok: false, requiresReboot: false };
      }
    },
  };
});
