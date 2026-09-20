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
  runAllTests: (durationSecs?: number) => Promise<void>;
  reset: () => void;
}

export const useNetworkStore = create<NetworkStore>((set, get) => ({
  stabilityStatus: "idle",
  stabilityResult: null,
  stabilityError: null,
  speedStatus: "idle",
  speedResult: null,
  speedError: null,
  bufferbloatStatus: "idle",
  bufferbloatResult: null,
  bufferbloatError: null,

  runAllTests: async (durationSecs = 10) => {
    const state = get();
    if ([state.stabilityStatus, state.speedStatus, state.bufferbloatStatus].includes("running")) return;
    // Idle latency must be sampled without our speed-test traffic. Bufferbloat
    // then controls its own idle and loaded phases without competing tests.
    await get().runStabilityTest(durationSecs);
    await get().runSpeedTest();
    await get().runBufferbloatTest();
  },

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
