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
  boostState: { robloxRunning: true, robloxForeground: true, processId: 1, fps: 60, ramTotal: 100, ramUsage: 50, cpuUsage: 10 },
  vpnState: { state:"connected", region:"mumbai", connectedAt:1, bytesUp:100, bytesDown:200, ping:30, pingReadings:0, gameRoute:null as {game_server_ip:string;estimated_path_ms:number;bypassed:boolean}|null },
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
    { getState: () => ({ ...h.boostState }) },
  ),
}));
vi.mock("../stores/vpnStore", () => ({
  useVpnStore: Object.assign(
    (select: (s: unknown) => unknown) => select({ fetchThroughput: h.throughput, fetchPing: h.ping }),
    { getState: () => ({ ...h.vpnState }) },
  ),
}));

import { useOverlayDriver } from "./useOverlayDriver";
import { useOverlayRuntimeStore } from "../stores/overlayRuntimeStore";

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((r, fail) => { resolve = r; reject = fail; });
  return { promise, resolve, reject };
}

function start() {
  useOverlayDriver();
  // Run the render effect; the position listener is unrelated to polling.
  return h.effects[0]() as () => void;
}

describe("overlay polling under slow native calls", () => {
  beforeEach(() => {
    vi.useFakeTimers({toFake:["setTimeout","clearTimeout","setInterval","clearInterval","Date","performance"]});
    vi.stubGlobal("window", globalThis);
    vi.stubGlobal("location", { search: "" });
    h.effects.length = 0;
    useOverlayRuntimeStore.setState({ error: null });
    h.overlay.enabled = true;
    h.overlay.metrics=["ping","upload"];
    h.vpnState={state:"connected",region:"mumbai",connectedAt:1,bytesUp:100,bytesDown:200,ping:30,pingReadings:0,gameRoute:null};
    h.gameIp="128.116.47.33";
    h.boostState={robloxRunning:true,robloxForeground:true,processId:1,fps:60,ramTotal:100,ramUsage:50,cpuUsage:10};
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

  it("shares window creation when the render effect restarts before it finishes", async () => {
    const pending = deferred();
    h.invoke.mockImplementation(command => command === "ensure_overlay_window" ? pending.promise : Promise.resolve());
    start()();
    const index = h.effects.length;
    useOverlayDriver();
    const stop = h.effects[index]() as () => void;
    const creations = h.invoke.mock.calls.filter(call => call[0] === "ensure_overlay_window").length;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(creations).toBe(1);
    expect(h.push).toHaveBeenCalledTimes(1);
  });

  it("forces a hovered or dragged overlay to hide when the player closes", async () => {
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.push.mock.calls[0][0]).toMatchObject({ enabled: true, forceHide: false });
    h.boostState.robloxRunning = false;
    h.boostState.robloxForeground = false;
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.push.mock.calls[1][0]).toMatchObject({ enabled: false, forceHide: true, values: {} });
    stop();
  });

  it("does not poll tunnel stats or the game monitor while no player is running", async () => {
    h.boostState.robloxRunning = false;
    h.boostState.robloxForeground = false;
    const stop = start();
    await vi.advanceTimersByTimeAsync(3000);
    stop();
    expect(h.metrics).toHaveBeenCalledTimes(4);
    expect(h.throughput).not.toHaveBeenCalled();
    expect(h.ping).not.toHaveBeenCalled();
    expect(h.invoke).toHaveBeenCalledTimes(1);
    expect(h.invoke).toHaveBeenCalledWith("ensure_overlay_window", {label:"overlay-stats"});
    expect(h.push.mock.calls.every(([payload])=>payload.forceHide && !payload.enabled)).toBe(true);
  });

  it.each(["closed", "replaced"] as const)("drops a sample if the player is %s during a slow monitor lookup", async state => {
    const pending = deferred();
    h.invoke.mockImplementation(command => command === "overlay_game_monitor" ? pending.promise : Promise.resolve());
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.invoke).toHaveBeenCalledWith("overlay_game_monitor");
    if (state === "closed") {
      h.boostState.robloxRunning = false;
      h.boostState.robloxForeground = false;
    } else h.boostState.processId = 2;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(h.push.mock.calls[0][0]).toMatchObject({enabled:false,forceHide:true,values:{}});
  });

  it("does not revive old metrics when a monitor lookup finishes after the freshness limit", async () => {
    const pending = deferred();
    h.invoke.mockImplementation(command => command === "overlay_game_monitor" ? pending.promise : Promise.resolve());
    const stop = start();
    await vi.advanceTimersByTimeAsync(6000);
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(h.push.mock.calls[0][0]).toMatchObject({enabled:false,forceHide:true,values:{}});
  });

  it.each(["throughput", "ping"] as const)("expires metrics while waiting for a slow %s read", async kind => {
    const pending = deferred();
    (kind === "throughput" ? h.throughput : h.ping).mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(6000);
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(h.push.mock.calls[0][0]).toMatchObject({enabled:false,forceHide:true,values:{}});
    expect(h.invoke).not.toHaveBeenCalledWith("overlay_game_monitor");
  });

  it("does not attribute a metrics sample to a different player appearing during a tunnel read", async () => {
    const pending = deferred();
    h.throughput.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    h.boostState.processId = 2;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(h.push.mock.calls[0][0]).toMatchObject({enabled:false,forceHide:true,values:{}});
    expect(h.invoke).not.toHaveBeenCalledWith("overlay_game_monitor");
  });

  it("keeps session elapsed time through a temporary metrics failure", async () => {
    h.overlay.metrics=["playtime"];
    h.metrics.mockResolvedValueOnce(true).mockResolvedValueOnce(false).mockResolvedValue(true);
    const stop = start();
    await vi.advanceTimersByTimeAsync(2000);
    stop();
    expect(h.push.mock.calls[1][0]).toMatchObject({enabled:false,forceHide:true});
    expect(h.push.mock.calls[2][0].values.playtime).toBe("00:02");
  });

  it.each([-3600000, 3600000])("keeps elapsed time and traffic rates correct when the system clock changes by %i ms", async jump => {
    h.overlay.metrics=["playtime","upload","ping"];
    h.ping.mockImplementationOnce(()=>{h.vpnState.pingReadings++;return Promise.resolve();});
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    vi.setSystemTime(Date.now() + jump);
    h.vpnState.bytesUp += 1024;
    await vi.advanceTimersByTimeAsync(1000);
    stop();
    expect(h.push.mock.calls[1][0].values).toMatchObject({playtime:"00:01",upload:"1.0 KB/s",ping:"30 ms"});
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

  it.each(["success", "failure"] as const)("ignores a replaced driver's late render %s when reporting overlay errors", async result => {
    const pending = deferred();
    h.push.mockReturnValueOnce(pending.promise);
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.push).toHaveBeenCalledTimes(1);
    stop();
    // A newer driver already owns this diagnostic. The old delivery has no
    // authority to clear or replace it after its effect has been cleaned up.
    useOverlayRuntimeStore.setState({ error: "The current overlay attempt failed. Retry." });
    if (result === "success") pending.resolve();
    else pending.reject(new Error("old delivery failed"));
    await vi.advanceTimersByTimeAsync(0);
    expect(useOverlayRuntimeStore.getState().error).toBe("The current overlay attempt failed. Retry.");
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
  it("starts a new traffic baseline and drops retained ping after reconnecting to the same relay", async () => {
    h.ping.mockImplementationOnce(() => { h.vpnState.pingReadings++; return Promise.resolve(); });
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    expect(h.push.mock.calls[0][0].values.ping).toBe("30 ms");
    h.vpnState.connectedAt = 2;
    h.vpnState.bytesUp = 2148;
    h.vpnState.pingReadings = 0;
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.push.mock.calls[1][0].values).toMatchObject({ upload: "--", ping: "--" });
    h.vpnState.bytesUp += 1024;
    await vi.advanceTimersByTimeAsync(1000);
    stop();
    expect(h.push.mock.calls[2][0].values.upload).toBe("1.0 KB/s");
  });
  it.each(["metrics", "monitor"] as const)("drops tunnel readings if the session changes during %s", async stage => {
    const pending = deferred();
    h.vpnState.gameRoute = { game_server_ip: h.gameIp, estimated_path_ms: 26, bypassed: false };
    h.ping.mockImplementation(() => { h.vpnState.pingReadings++; return Promise.resolve(); });
    if (stage === "metrics") h.metrics.mockReturnValueOnce(pending.promise.then(() => true));
    else h.invoke.mockImplementation(command => command === "overlay_game_monitor" ? pending.promise : Promise.resolve());
    const stop = start();
    await vi.advanceTimersByTimeAsync(0);
    h.vpnState.connectedAt = 2;
    h.vpnState.bytesUp += 2048;
    pending.resolve();
    await vi.advanceTimersByTimeAsync(0);
    stop();
    expect(h.push.mock.calls[0][0].values).toMatchObject({ upload: "--", ping: "--", game_ping: "--" });
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
