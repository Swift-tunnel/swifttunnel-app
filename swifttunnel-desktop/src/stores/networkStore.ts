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

export const useNetworkStore = create<NetworkStore>((set) => {
  let stabilityRunSeq = 0;
  let speedRunSeq = 0;
  let bufferbloatRunSeq = 0;

  return {
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
        if (runId === stabilityRunSeq) {
          set({
            stabilityStatus: "complete",
            stabilityResult: result,
            stabilityError: null,
          });
        }
      } catch (e) {
        if (runId === stabilityRunSeq) {
          set({
            stabilityStatus: "error",
            stabilityResult: null,
            stabilityError: String(e),
          });
        }
      }
    },

    runSpeedTest: async () => {
      const runId = ++speedRunSeq;
      try {
        set({ speedStatus: "running", speedResult: null, speedError: null });
        const result = await networkStartSpeedTest();
        if (runId === speedRunSeq) {
          set({
            speedStatus: "complete",
            speedResult: result,
            speedError: null,
          });
        }
      } catch (e) {
        if (runId === speedRunSeq) {
          set({
            speedStatus: "error",
            speedResult: null,
            speedError: String(e),
          });
        }
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
        if (runId === bufferbloatRunSeq) {
          set({
            bufferbloatStatus: "complete",
            bufferbloatResult: result,
            bufferbloatError: null,
          });
        }
      } catch (e) {
        if (runId === bufferbloatRunSeq) {
          set({
            bufferbloatStatus: "error",
            bufferbloatResult: null,
            bufferbloatError: String(e),
          });
        }
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
  };
});
