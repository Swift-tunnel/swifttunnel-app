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
    try {
      set({
        stabilityStatus: "running",
        stabilityResult: null,
        stabilityError: null,
      });
      const result = await networkStartStabilityTest(durationSecs);
      set({ stabilityStatus: "complete", stabilityResult: result });
    } catch (e) {
      set({ stabilityStatus: "error", stabilityError: String(e) });
    }
  },

  runSpeedTest: async () => {
    try {
      set({ speedStatus: "running", speedResult: null, speedError: null });
      const result = await networkStartSpeedTest();
      set({ speedStatus: "complete", speedResult: result });
    } catch (e) {
      set({ speedStatus: "error", speedError: String(e) });
    }
  },

  runBufferbloatTest: async () => {
    try {
      set({
        bufferbloatStatus: "running",
        bufferbloatResult: null,
        bufferbloatError: null,
      });
      const result = await networkStartBufferbloatTest();
      set({ bufferbloatStatus: "complete", bufferbloatResult: result });
    } catch (e) {
      set({ bufferbloatStatus: "error", bufferbloatError: String(e) });
    }
  },

  reset: () => {
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
