import { create } from "zustand";
import type {
  StabilityResultResponse,
  SpeedResultResponse,
  BufferbloatResultResponse,
} from "../lib/types";
import {
  networkStartStabilityTest,
  networkStartSpeedTest,
  networkStartBufferbloatTest,
} from "../lib/commands";

type TestStatus = "idle" | "running" | "complete" | "error";

interface NetworkStore {
  // Stability test
  stabilityStatus: TestStatus;
  stabilityResult: StabilityResultResponse | null;
  stabilityError: string | null;

  // Speed test
  speedStatus: TestStatus;
  speedResult: SpeedResultResponse | null;
  speedError: string | null;

  // Bufferbloat test
  bufferbloatStatus: TestStatus;
  bufferbloatResult: BufferbloatResultResponse | null;
  bufferbloatError: string | null;

  // Actions
  runStabilityTest: (durationSecs?: number) => Promise<void>;
  runSpeedTest: () => Promise<void>;
  runBufferbloatTest: () => Promise<void>;
  reset: () => void;
}

let stabilityRunSeq = 0;
let speedRunSeq = 0;
let bufferbloatRunSeq = 0;

export const useNetworkStore = create<NetworkStore>((set) => ({
  stabilityStatus: "idle",
  stabilityResult: null,
  stabilityError: null,
  speedStatus: "idle",
  speedResult: null,
  speedError: null,
  bufferbloatStatus: "idle",
  bufferbloatResult: null,
  bufferbloatError: null,

  runStabilityTest: async (durationSecs = 10) => {
    const runId = ++stabilityRunSeq;
    try {
      set({
        stabilityStatus: "running",
        stabilityResult: null,
        stabilityError: null,
      });
      const result = await networkStartStabilityTest(durationSecs);
      set(() =>
        runId === stabilityRunSeq
          ? { stabilityStatus: "complete", stabilityResult: result }
          : {},
      );
    } catch (e) {
      set(() =>
        runId === stabilityRunSeq
          ? { stabilityStatus: "error", stabilityError: String(e) }
          : {},
      );
    }
  },

  runSpeedTest: async () => {
    const runId = ++speedRunSeq;
    try {
      set({ speedStatus: "running", speedResult: null, speedError: null });
      const result = await networkStartSpeedTest();
      set(() =>
        runId === speedRunSeq
          ? { speedStatus: "complete", speedResult: result }
          : {},
      );
    } catch (e) {
      set(() =>
        runId === speedRunSeq
          ? { speedStatus: "error", speedError: String(e) }
          : {},
      );
    }
  },

  runBufferbloatTest: async () => {
    const runId = ++bufferbloatRunSeq;
    try {
      set({
        bufferbloatStatus: "running",
        bufferbloatResult: null,
        bufferbloatError: null,
      });
      const result = await networkStartBufferbloatTest();
      set(() =>
        runId === bufferbloatRunSeq
          ? {
              bufferbloatStatus: "complete",
              bufferbloatResult: result,
            }
          : {},
      );
    } catch (e) {
      set(() =>
        runId === bufferbloatRunSeq
          ? {
              bufferbloatStatus: "error",
              bufferbloatError: String(e),
            }
          : {},
      );
    }
  },

  reset: () => {
    stabilityRunSeq++;
    speedRunSeq++;
    bufferbloatRunSeq++;
    set({
      stabilityStatus: "idle",
      stabilityResult: null,
      stabilityError: null,
      speedStatus: "idle",
      speedResult: null,
      speedError: null,
      bufferbloatStatus: "idle",
      bufferbloatResult: null,
      bufferbloatError: null,
    });
  },
}));
