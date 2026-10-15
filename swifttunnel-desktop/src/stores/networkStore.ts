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
  networkCancelTest,
} from "../lib/commands";

type TestStatus = "idle" | "running" | "complete" | "error";

interface NetworkStore {
  isRunning: boolean;
  isCancelling: boolean;
  cancelError: string | null;
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
  cancelTests: () => Promise<void>;
  reset: () => void;
}

export const useNetworkStore = create<NetworkStore>((set, get) => {
  type Run = { id: string; cancelled: boolean };
  let currentRun: Run | null = null;
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

  async function exclusive(work: (run: Run) => Promise<void>) {
    if (currentRun || get().isRunning) return;
    const run: Run = { id: crypto.randomUUID(), cancelled: false };
    currentRun = run;
    set({ isRunning: true, isCancelling: false, cancelError: null });
    try {
      await work(run);
    } finally {
      if (currentRun === run) {
        currentRun = null;
        set(state => ({
          isRunning: false,
          isCancelling: false,
          ...(run.cancelled ? {
            stabilityStatus: state.stabilityStatus === "running" ? "idle" : state.stabilityStatus,
            speedStatus: state.speedStatus === "running" ? "idle" : state.speedStatus,
            bufferbloatStatus: state.bufferbloatStatus === "running" ? "idle" : state.bufferbloatStatus,
          } : {}),
        }));
      }
    }
  }

  async function stability(run: Run, durationSecs: number) {
    if (run.cancelled) return;
    try {
      set({
        stabilityStatus: "running",
        stabilityResult: null,
        stabilityError: null,
      });
      const result = await networkStartStabilityTest(durationSecs, run.id);
      if (!run.cancelled) set({ stabilityStatus: "complete", stabilityResult: result });
    } catch (e) {
      if (!run.cancelled) set({ stabilityStatus: "error", stabilityError: formatErrorMessage(e) });
    }
  }

  async function speed(run: Run) {
    if (run.cancelled) return;
    try {
      set({ speedStatus: "running", speedResult: null, speedError: null });
      const result = await networkStartSpeedTest(run.id);
      if (!run.cancelled) set({ speedStatus: "complete", speedResult: result });
    } catch (e) {
      if (!run.cancelled) set({ speedStatus: "error", speedError: formatErrorMessage(e) });
    }
  }

  async function bufferbloat(run: Run) {
    if (run.cancelled) return;
    try {
      set({
        bufferbloatStatus: "running",
        bufferbloatResult: null,
        bufferbloatError: null,
      });
      const result = await networkStartBufferbloatTest(run.id);
      if (!run.cancelled) set({ bufferbloatStatus: "complete", bufferbloatResult: result });
    } catch (e) {
      if (!run.cancelled) set({ bufferbloatStatus: "error", bufferbloatError: formatErrorMessage(e) });
    }
  }

  return {
    ...emptyResults,
    isRunning: false,
    isCancelling: false,
    cancelError: null,
    runAllTests: (durationSecs = 10) => exclusive(async (run) => {
      set(emptyResults);
      // One permit covers idle sampling and all loaded phases, including
      // the gaps between tests. Prior grades do not belong to this run.
      await stability(run, durationSecs);
      await speed(run);
      await bufferbloat(run);
    }),
    runStabilityTest: (durationSecs = 10) => exclusive((run) => stability(run, durationSecs)),
    runSpeedTest: () => exclusive(speed),
    runBufferbloatTest: () => exclusive(bufferbloat),
    cancelTests: async () => {
      const run = currentRun;
      if (!run || run.cancelled) return;
      run.cancelled = true;
      set({ isCancelling: true, cancelError: null });
      try {
        await networkCancelTest(run.id);
        // The native command's reply releases the permit. A Stop acknowledgement
        // alone does not prove that its load workers have finished unwinding.
      } catch (error) {
        if (currentRun === run) {
          run.cancelled = false;
          set({ isCancelling: false, cancelError: formatErrorMessage(error) });
        }
      }
    },
    reset: () => {
      // This is a display reset, not native cancellation. Never unlock work
      // which is still using the network.
      if (!get().isRunning) set({ ...emptyResults, cancelError: null });
    },
  };
});
