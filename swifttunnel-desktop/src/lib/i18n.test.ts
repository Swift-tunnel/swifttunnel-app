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

beforeEach(() => {
  vi.resetModules();
  nodes = [];
  storage = new Map();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
  });
  vi.stubGlobal("NodeFilter", { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2 });
  vi.stubGlobal("document", {
    body: {},
    createTreeWalker: (_root: unknown, _mask: number, filter?: { acceptNode(node: Node): number }) => {
      const visible = nodes.filter((node) => !filter || filter.acceptNode(node as unknown as Node) === 1);
      let index = 0;
      return { nextNode: () => visible[index++] ?? null };
    },
  });
  vi.stubGlobal("MutationObserver", class { observe() {} disconnect() {} });
  invoke.mockImplementation(async (_cmd, args: { text: string }) =>
    args.text.split("\n").map((line) => `FR:${line}`).join("\n"));
});
afterEach(() => vi.unstubAllGlobals());

describe("runtime translation lifecycle", () => {
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
