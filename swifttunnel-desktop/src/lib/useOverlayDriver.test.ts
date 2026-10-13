import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  effects: [] as Array<() => void | (() => void)>,
  invoke: vi.fn(),
  listen: vi.fn(),
  push: vi.fn(),
  metrics: vi.fn(),
  throughput: vi.fn(),
  ping: vi.fn(),
  update: vi.fn(), save: vi.fn(),
  gameIp: "128.116.47.33",
  vpnState: { state:"connected", region:"mumbai", bytesUp:100, bytesDown:200, ping:30, pingReadings:0, gameRoute:null as {game_server_ip:string;estimated_path_ms:number;bypassed:boolean}|null },
  overlay: { enabled: true, metrics: ["ping", "upload"], size: "medium", color: "white", style: "solid", position: "top-left", custom_x: 0, custom_y: 0 },
}));

vi.mock("react", () => ({
  useEffect: (effect: () => void | (() => void)) => { h.effects.push(effect); },
  useRef: (current: unknown) => ({ current }),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: h.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: h.listen }));
vi.mock("../components/ingame/overlayBus", () => ({
  OVERLAY_POSITION_EVENT: "position",
  pushOverlayRender: h.push,
}));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: Object.assign((select: (s: unknown) => unknown) => select({
    settings: { config: { overlay: h.overlay } }, update: h.update, save: h.save,
  }), {getState:()=>({settings:{config:{overlay:h.overlay}},update:h.update,save:h.save})}),
}));
vi.mock("../stores/gameLibraryStore",()=>({useGameLibraryStore:{getState:()=>({library:{current:{ip:h.gameIp}}})}}));
vi.mock("../stores/boostStore", () => ({
  useBoostStore: Object.assign(
    (select: (s: unknown) => unknown) => select({ fetchMetrics: h.metrics }),
    { getState: () => ({ robloxRunning: true, robloxForeground: true, fps: 60, ramTotal: 100, ramUsage: 50, cpuUsage: 10 }) },
  ),
}));
vi.mock("../stores/vpnStore", () => ({
  useVpnStore: Object.assign(
    (select: (s: unknown) => unknown) => select({ fetchThroughput: h.throughput, fetchPing: h.ping }),
    { getState: () => ({ ...h.vpnState }) },
  ),
}));

import { useOverlayDriver } from "./useOverlayDriver";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

function start() {
  useOverlayDriver();
  // Run the render effect; the position listener is unrelated to polling.
  return h.effects[0]() as () => void;
}

describe("overlay polling under slow native calls", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal("window", globalThis);
    h.effects.length = 0;
    h.overlay.enabled = true;
    h.overlay.metrics=["ping","upload"];
    h.vpnState={state:"connected",region:"mumbai",bytesUp:100,bytesDown:200,ping:30,pingReadings:0,gameRoute:null};
    h.gameIp="128.116.47.33";
    h.invoke.mockResolvedValue(undefined);
    h.metrics.mockResolvedValue(true);
    h.throughput.mockResolvedValue(true);
    h.ping.mockResolvedValue(undefined);
    h.push.mockResolvedValue(undefined);
    h.listen.mockResolvedValue(()=>{});
    h.save.mockResolvedValue(undefined);
    h.update.mockImplementation(change=>Object.assign(h.overlay,change.config.overlay));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("does not accumulate ticks while window creation is stalled", async () => {
    const pending = deferred();
    h.invoke.mockReturnValue(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    const calls = h.push.mock.calls.length;
    stop();
    expect(calls).toBe(1);
  });

  it("keeps one tick pending during a slow metrics sample and resumes", async () => {
    const pending = deferred();
    h.metrics.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    const calls = h.metrics.mock.calls.length;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(calls).toBe(1);
    expect(h.push).toHaveBeenCalledTimes(2);
  });

  it.each(["metrics", "throughput", "ping"] as const)(
    "does not show the overlay after disabling it during %s",
    async (stage) => {
      const pending = deferred();
      h[stage].mockReturnValue(pending.promise);
      const stop = start();
      await vi.advanceTimersByTimeAsync(0);
      stop();
      pending.resolve();
      await vi.advanceTimersByTimeAsync(2_000);
      expect(h.push).not.toHaveBeenCalled();
      if (stage === "metrics") expect(h.throughput).not.toHaveBeenCalled();
      if (stage !== "ping") expect(h.ping).not.toHaveBeenCalled();
    },
  );

  it("also waits for render delivery before collecting another sample", async () => {
    const pending = deferred();
    h.push.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(60_000);
    const calls = h.metrics.mock.calls.length;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(calls).toBe(1);
    expect(h.push).toHaveBeenCalledTimes(2);
  });

  it("resumes after a failed metrics sample", async () => {
    h.metrics.mockRejectedValueOnce(new Error("sampler unavailable"));
    const stop = start();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(h.metrics).toHaveBeenCalledTimes(2);
    expect(h.push).toHaveBeenCalledTimes(2);
    expect(h.push.mock.calls[0][0]).toMatchObject({ enabled: false, forceHide: true });
    expect(h.push.mock.calls[1][0]).toMatchObject({ enabled: true, forceHide: false });
  });

  it("hides stale foreground state when the metrics store reports failure", async () => {
    h.metrics.mockResolvedValueOnce(false);
    const stop = start();
    await vi.advanceTimersByTimeAsync(1_000);
    stop();
    expect(h.push.mock.calls[0][0]).toMatchObject({ enabled: false, forceHide: true });
    expect(h.push.mock.calls[1][0]).toMatchObject({ enabled: true, forceHide: false });
  });

  it("explicit disable cancels an overlay interaction even without another tick", async () => {
    h.overlay.enabled = false;
    start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(h.push).toHaveBeenCalledTimes(1);
    expect(h.push.mock.calls[0][0]).toMatchObject({ enabled: false, forceHide: true });
    expect(h.metrics).not.toHaveBeenCalled();
  });
  it("does not create a window or poll for legacy selections with no supported metrics",async()=>{
    h.overlay.metrics=["gpu","cpu_temp"];
    start(); await vi.advanceTimersByTimeAsync(1000);
    expect(h.invoke).not.toHaveBeenCalled();
    expect(h.metrics).not.toHaveBeenCalled();
    expect(h.push.mock.calls[0][0]).toMatchObject({enabled:false,forceHide:true,metrics:[]});
  });
  it("only shows an estimated game ping when it matches the current destination", async()=>{
    h.overlay.metrics=["game_ping"];
    h.vpnState.gameRoute={game_server_ip:h.gameIp,estimated_path_ms:26,bypassed:false};
    const stop=start(); await vi.advanceTimersByTimeAsync(0);
    expect(h.push.mock.calls[0][0].values.game_ping).toBe("~26 ms");
    h.vpnState.gameRoute.game_server_ip="128.116.46.33";
    await vi.advanceTimersByTimeAsync(1000); stop();
    expect(h.push.mock.calls[1][0].values.game_ping).toBe("--");
  });
  it("expires retained relay readings instead of displaying them indefinitely",async()=>{
    h.ping.mockImplementationOnce(()=>{h.vpnState.pingReadings++;return Promise.resolve();});
    const stop=start(); await vi.advanceTimersByTimeAsync(0);
    expect(h.push.mock.calls[0][0].values.ping).toBe("30 ms");
    await vi.advanceTimersByTimeAsync(6000); stop();
    expect(h.push.mock.calls[h.push.mock.calls.length-1]?.[0].values.ping).toBe("--");
  });
  it("does not turn a failed throughput sample into a zero traffic reading",async()=>{
    h.throughput.mockResolvedValue(false);
    const stop=start(); await vi.advanceTimersByTimeAsync(1000); stop();
    expect(h.push.mock.calls[h.push.mock.calls.length-1]?.[0].values.upload).toBe("--");
  });
  it("registers the hotkey after its listener and toggles the latest overlay preference",async()=>{
    useOverlayDriver(); const stop=h.effects[2]() as ()=>void;
    await vi.advanceTimersByTimeAsync(0);
    expect(h.invoke).toHaveBeenCalledWith("ensure_overlay_shortcut");
    const listener=h.listen.mock.calls[0][1];
    listener(); expect(h.overlay.enabled).toBe(false);
    listener(); expect(h.overlay.enabled).toBe(true);
    expect(h.save).toHaveBeenCalledTimes(2); stop();
  });
});
