import { create } from "zustand";
import { formatErrorMessage } from "../lib/errors";
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
  isRunning: boolean;
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

export const useNetworkStore = create<NetworkStore>((set, get) => {
  const emptyResults = {
  stabilityStatus: "idle",
  stabilityResult: null,
  stabilityError: null,
  speedStatus: "idle",
  speedResult: null,
  speedError: null,
  bufferbloatStatus: "idle",
  bufferbloatResult: null,
  bufferbloatError: null,
  } as const;

  async function exclusive(work: () => Promise<void>) {
    if (get().isRunning) return;
    set({ isRunning: true });
    try { await work(); } finally { set({ isRunning: false }); }
  }

  async function stability(durationSecs: number) {
    try {
      set({
        stabilityStatus: "running",
        stabilityResult: null,
        stabilityError: null,
      });
      const result = await networkStartStabilityTest(durationSecs);
      set({ stabilityStatus: "complete", stabilityResult: result });
    } catch (e) {
      set({ stabilityStatus: "error", stabilityError: formatErrorMessage(e) });
    }
  }

  async function speed() {
    try {
      set({ speedStatus: "running", speedResult: null, speedError: null });
      const result = await networkStartSpeedTest();
      set({ speedStatus: "complete", speedResult: result });
    } catch (e) {
      set({ speedStatus: "error", speedError: formatErrorMessage(e) });
    }
  }

  async function bufferbloat() {
    try {
      set({
        bufferbloatStatus: "running",
        bufferbloatResult: null,
        bufferbloatError: null,
      });
      const result = await networkStartBufferbloatTest();
      set({ bufferbloatStatus: "complete", bufferbloatResult: result });
    } catch (e) {
      set({ bufferbloatStatus: "error", bufferbloatError: formatErrorMessage(e) });
    }
  }

  return {
    ...emptyResults,
    isRunning: false,
    runAllTests: (durationSecs = 10) => exclusive(async () => {
      set(emptyResults);
      // One permit covers idle sampling and all loaded phases, including
      // the gaps between tests. Prior grades do not belong to this run.
      await stability(durationSecs);
      await speed();
      await bufferbloat();
    }),
    runStabilityTest: (durationSecs = 10) => exclusive(() => stability(durationSecs)),
    runSpeedTest: () => exclusive(speed),
    runBufferbloatTest: () => exclusive(bufferbloat),
    reset: () => {
      // This is a display reset, not native cancellation. Never unlock work
      // which is still using the network.
      if (!get().isRunning) set(emptyResults);
    },
  };
});
