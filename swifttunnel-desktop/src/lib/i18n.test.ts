import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

// Exercise translation against text-node identities reused by React. The
// walker visits only the current document, just as a browser TreeWalker does.
function text(value: string) {
  return {
    nodeValue: value,
    isConnected: true,
    parentElement: { tagName: "SPAN", closest: () => null },
  };
}

let nodes: ReturnType<typeof text>[];
let storage: Map<string, string>;
let observeChanges: (records: unknown[]) => void;
let walks: number;

beforeEach(() => {
  vi.resetModules();
  nodes = [];
  walks = 0;
  vi.useFakeTimers();
  vi.stubGlobal("window", { setTimeout, clearTimeout });
  storage = new Map();
  vi.stubGlobal("localStorage", {
    get length() { return storage.size; },
    key: (index: number) => [...storage.keys()][index] ?? null,
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
  });
  vi.stubGlobal("NodeFilter", { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2 });
  vi.stubGlobal("document", {
    body: {},
    createTreeWalker: (_root: unknown, _mask: number, filter?: { acceptNode(node: Node): number }) => {
      walks++;
      const visible = nodes.filter((node) => !filter || filter.acceptNode(node as unknown as Node) === 1);
      let index = 0;
      return { nextNode: () => visible[index++] ?? null };
    },
  });
  vi.stubGlobal("MutationObserver", class { constructor(callback: (records: unknown[]) => void) { observeChanges = callback; } observe() {} disconnect() {} });
  invoke.mockImplementation(async (_cmd, args: { text: string }) =>
    args.text.split("\n").map((line) => `FR:${line}`).join("\n"));
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it("splits long labels by encoded bytes instead of poisoning a whole oversized batch", async () => {
  for (let i = 0; i < 40; i++) nodes.push(text(`Setting ${i}: ` + "x".repeat(1200)));
  invoke.mockImplementation(async (_command, args) => {
    if (new TextEncoder().encode(args.text).byteLength > 32 * 1024) throw new Error("Request too large");
    return args.text.split("\n").map((line: string) => `FR:${line}`).join("\n");
  });
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  expect(invoke.mock.calls.length).toBeGreaterThan(1);
  expect(nodes.every(node => node.nodeValue.startsWith("FR:"))).toBe(true);
});

it("keeps saved dictionaries bounded while live translated nodes survive cache eviction", async () => {
  for (let i = 0; i < 600; i++) nodes.push(text(`Setting ${i}: ` + "x".repeat(1900)));
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  await vi.advanceTimersByTimeAsync(2000);
  expect(nodes.every(node => node.nodeValue.startsWith("FR:"))).toBe(true);
  expect(storage.get("st.i18n.fr")!.length).toBeLessThanOrEqual(1024 * 1024);
  const completedCalls = invoke.mock.calls.length;
  await i18n.applyLanguage("fr");
  await vi.advanceTimersByTimeAsync(1000);
  expect(invoke).toHaveBeenCalledTimes(completedCalls);
});

it("leaves oversized UI text alone instead of requesting and retaining it", async () => {
  const large = text("Error: " + "x".repeat(100000));
  nodes.push(large);
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  expect(invoke).not.toHaveBeenCalled();
  expect(large.nodeValue).toHaveLength(100007);
});

it("translates labels inside a large mounted container without flattening its whole text", async () => {
  nodes.push(text("Connected"));
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  const added = Array.from({ length: 60 }, (_, i) => text(`New control ${i}: ` + "x".repeat(100)));
  nodes = added;
  const container = { nodeValue: null, tagName: "DIV", closest: () => null,
    get textContent(): string { throw new Error("observer flattened a whole page"); } };
  observeChanges([{ type: "childList", addedNodes: [container] }]);
  await vi.advanceTimersByTimeAsync(1000);
  expect(added.every(node => node.nodeValue.startsWith("FR:"))).toBe(true);
});

it("does not use corrupt language values as cache keys or translation requests", async () => {
  nodes.push(text("Connected"));
  storage.set("st.lang", "x".repeat(100000));
  const i18n = await import("./i18n");
  expect(i18n.getStoredLang()).toBe("en");
  i18n.initI18n();
  await i18n.applyLanguage("../../bad");
  expect(invoke).not.toHaveBeenCalled();
  expect(nodes[0].nodeValue).toBe("Connected");
});

it("does not apply or persist an oversized translation service answer", async () => {
  nodes.push(text("Connected"));
  invoke.mockResolvedValue("x".repeat(8193));
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  await vi.advanceTimersByTimeAsync(1000);
  expect(nodes[0].nodeValue).toBe("Connected");
  expect(JSON.parse(storage.get("st.i18n.fr")!).Connected).toBe("Connected");
  expect(invoke).toHaveBeenCalledTimes(1);
});

it("does not loop when an offline page has more labels than the retained failure history", async () => {
  for (let i = 0; i < 3000; i++) nodes.push(text(`Setting ${i}`));
  invoke.mockRejectedValue(new Error("offline"));
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  await vi.advanceTimersByTimeAsync(3000);
  expect(invoke).toHaveBeenCalledTimes(1);
});

it("refreshes live nodes after an explicit cache reset", async () => {
  nodes.push(text("Connected"));
  const i18n = await import("./i18n");
  await i18n.applyLanguage("fr");
  invoke.mockResolvedValue("Updated translation");
  await i18n.resetTranslationCache();
  expect(nodes[0].nodeValue).toBe("Updated translation");
  expect(invoke).toHaveBeenLastCalledWith("i18n_translate", { text: "Connected", targetLang: "fr" });
});

it("does not let an obsolete failed request poison a freshly reset translation pass", async () => {
  nodes.push(text("Connected"));
  let failOld!: (error: Error) => void;
  invoke.mockReturnValueOnce(new Promise((_resolve, reject) => { failOld = reject; }));
  const i18n = await import("./i18n");
  const old = i18n.applyLanguage("fr");
  await i18n.resetTranslationCache();
  failOld(new Error("old request failed"));
  await old;
  await vi.advanceTimersByTimeAsync(1000);
  expect(invoke).toHaveBeenCalledTimes(2);
  expect(nodes[0].nodeValue).toBe("FR:Connected");
});

describe("runtime translation lifecycle", () => {
  it("ignores damaged cache entries while retaining valid saved translations", async () => {
    storage.set("st.i18n.fr", JSON.stringify({
      Connected: { wrong: "object" }, Disconnected: 42,
      Waiting: null, Play: "", Ready: "Prêt",
    }));
    nodes.push(text("Connected"), text("Disconnected"), text("Waiting"), text("Play"), text("Ready"));
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    expect(nodes.map(node => node.nodeValue)).toEqual(["FR:Connected", "FR:Disconnected", "FR:Waiting", "FR:Play", "Prêt"]);
    expect(invoke).toHaveBeenCalledTimes(1);
    const repaired = JSON.parse(storage.get("st.i18n.fr")!);
    expect(repaired.Connected).toBe("FR:Connected");
    expect(repaired.Ready).toBe("Prêt");
  });

  it.each(["null", '["bad dictionary"]', " ".repeat(1024 * 1024) + '{"Connected":"stale"}'])(
    "recovers from a non-dictionary or oversized cache %#", async (raw) => {
      storage.set("st.i18n.fr", raw);
      nodes.push(text("Connected"));
      const i18n = await import("./i18n");
      await i18n.applyLanguage("fr");
      expect(nodes[0].nodeValue).toBe("FR:Connected");
      expect(invoke).toHaveBeenCalledTimes(1);
    },
  );

  it("does not turn an offline batch into forty individual requests", async () => {
    nodes.push(...Array.from({ length: 40 }, (_, i) => text(`Setting number ${i}`)));
    invoke.mockRejectedValue(new Error("Network unavailable"));
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    await i18n.applyLanguage("fr");
    await vi.advanceTimersByTimeAsync(1000);
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(nodes[0].nodeValue).toBe("Setting number 0");
  });

  it("stops the per-item fallback when a language request becomes obsolete", async () => {
    nodes.push(text("Connected"), text("Play normally"));
    let finish!: (value: string) => void;
    invoke.mockReturnValueOnce(new Promise<string>(resolve => { finish = resolve; }));
    const i18n = await import("./i18n");
    const pending = i18n.applyLanguage("fr");
    await i18n.applyLanguage("en");
    finish("Wrong number of segments");
    await pending;
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(nodes[0].nodeValue).toBe("Connected");
  });
  it("does not rescan the document for changing live counters", async () => {
    nodes.push(text("Connected"));
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    const initialWalks = walks;
    for (const value of ["22 ms", "120 FPS", "2h 59m", "14.2 MB/s"]) {
      observeChanges([{ type: "characterData", target: text(value) }]);
      observeChanges([{ type: "childList", addedNodes: [text(value)] }]);
    }
    await vi.advanceTimersByTimeAsync(500);
    expect(walks).toBe(initialWalks);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("translates new controls mounted during an outstanding request", async () => {
    nodes.push(text("Connected"));
    let finish!: (value: string) => void;
    invoke.mockReturnValueOnce(new Promise<string>(resolve => { finish = resolve; }));
    const i18n = await import("./i18n");
    const pending = i18n.applyLanguage("fr");
    const added = text("Play normally");
    nodes.push(added);
    observeChanges([{ type: "childList", addedNodes: [added] }]);
    await vi.advanceTimersByTimeAsync(300);
    finish("FR:Connected");
    await pending;
    await vi.advanceTimersByTimeAsync(300);
    expect(added.nodeValue).toBe("FR:Play normally");
    expect(invoke).toHaveBeenCalledTimes(2);
  });
  it("does not request or persist translations for changing live measurements", async () => {
    const node = text("1.0 MB/s");
    nodes.push(node);
    const i18n = await import("./i18n");
    const samples = ["<1m", "2h 14m", "47m", "23 ms", "120 FPS", "1.2 GB"];
    for (let i = 0; i < 120; i++) samples.push(`${i}.5 KB/s`);
    for (const sample of samples) {
      node.nodeValue = sample;
      await i18n.applyLanguage("fr");
      expect(node.nodeValue).toBe(sample);
    }
    expect(invoke).not.toHaveBeenCalled();
    expect(storage.has("st.i18n.fr")).toBe(false);
  });

  it("still translates prose containing a number", async () => {
    const node = text("Retry in 3 seconds");
    nodes.push(node);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    expect(node.nodeValue).toBe("FR:Retry in 3 seconds");
  });

  it("translates the new connection status when React reuses a text node", async () => {
    const node = text("Disconnected");
    nodes.push(node);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    expect(node.nodeValue).toBe("FR:Disconnected");
    node.nodeValue = "Connected";
    await i18n.applyLanguage("fr");
    expect(node.nodeValue).toBe("FR:Connected");
    await i18n.applyLanguage("en");
    expect(node.nodeValue).toBe("Connected");
  });

  it("does not overwrite a newer React update when restoring English", async () => {
    const node = text("Connecting");
    nodes.push(node);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    node.nodeValue = "Connected";
    await i18n.applyLanguage("en");
    expect(node.nodeValue).toBe("Connected");
  });

  it("does not revisit removed tab nodes on English restoration", async () => {
    const removed = text("Old tab");
    nodes.push(removed);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    const inspected = vi.fn(() => false);
    Object.defineProperty(removed, "isConnected", { get: inspected });
    nodes = [text("Current tab")];
    await i18n.applyLanguage("fr");
    await i18n.applyLanguage("en");
    expect(inspected).not.toHaveBeenCalled();
    expect(nodes[0].nodeValue).toBe("Current tab");
  });

  it("restores the original across two translated languages", async () => {
    const node = text("  Connected  ");
    nodes.push(node);
    invoke.mockImplementation(async (_cmd, args) => `${args.targetLang}:${args.text}`);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    await i18n.applyLanguage("de");
    expect(node.nodeValue).toBe("  de:Connected  ");
    await i18n.applyLanguage("en");
    expect(node.nodeValue).toBe("  Connected  ");
  });

  it("handles a language whose translation equals the English source", async () => {
    const node = text("Connected");
    nodes.push(node);
    invoke.mockImplementation(async (_cmd, args) => args.targetLang === "de" ? args.text : `FR:${args.text}`);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    await i18n.applyLanguage("de");
    expect(node.nodeValue).toBe("Connected");
  });

  it("leaves a new numeric value or protected identifier intact", async () => {
    const node = text("Connecting");
    nodes.push(node);
    const i18n = await import("./i18n");
    await i18n.applyLanguage("fr");
    node.nodeValue = "123";
    await i18n.applyLanguage("fr");
    expect(node.nodeValue).toBe("123");
    node.nodeValue = "person@example.test";
    await i18n.applyLanguage("fr");
    await i18n.applyLanguage("en");
    expect(node.nodeValue).toBe("person@example.test");
  });

  it("does not apply stale fetched text over a React change", async () => {
    const node = text("Connecting");
    nodes.push(node);
    let finish!: (value: string) => void;
    invoke.mockReturnValueOnce(new Promise<string>((resolve) => { finish = resolve; }));
    const i18n = await import("./i18n");
    const pending = i18n.applyLanguage("fr");
    node.nodeValue = "Connected";
    finish("FR:Connecting");
    await pending;
    expect(node.nodeValue).toBe("Connected");
  });
});
