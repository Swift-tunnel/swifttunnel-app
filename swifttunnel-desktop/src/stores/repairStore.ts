import { create } from "zustand";
import { parseRepairRun, type RepairRun, type RepairItemResult } from "../lib/repairRun";
import type { RepairReport } from "../lib/repairCenter";

const STORAGE_KEY = "swifttunnel.lastRepairAll.v1";
function savedRun(): RepairRun | null {
  try { return parseRepairRun(localStorage.getItem(STORAGE_KEY)); } catch { return null; }
}

interface RepairState {
  running: boolean;
  restarting: boolean;
  reinstalling: boolean;
  progress: number;
  currentStep: string | null;
  error: string | null;
  liveItems: RepairItemResult[];
  lastRun: RepairRun | null;
  reinstallReport: RepairReport | null;
}

// Operations outlive the tab. Navigating away must not unlock a second run.
export const useRepairStore = create<RepairState>(() => ({
  running: false, restarting: false, reinstalling: false, progress: 0,
  currentStep: null, error: null, liveItems: [], lastRun: savedRun(), reinstallReport: null,
}));

export function repairIsBusy(): boolean {
  const state = useRepairStore.getState();
  return state.running || state.reinstalling || state.restarting;
}

export function beginRepair(kind: "repair" | "reinstall"): boolean {
  if (repairIsBusy()) return false;
  useRepairStore.setState({
    running: kind === "repair", reinstalling: kind === "reinstall",
    progress: 0, currentStep: "Disconnecting the tunnel", error: null, liveItems: [],
  });
  return true;
}

export function saveRepairRun(run: RepairRun): void {
  useRepairStore.setState({ lastRun: run });
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(run)); } catch { /* Keep the in-memory report. */ }
}
