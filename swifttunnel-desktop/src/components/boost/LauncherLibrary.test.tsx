import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { GameLibraryPanel } from "./LauncherLibrary";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";

vi.mock("../../stores/gameLibraryStore", async () => {
  const actual = await vi.importActual<typeof import("../../stores/gameLibraryStore")>("../../stores/gameLibraryStore");
  return { useGameLibraryStore: Object.assign((selector?: (state: ReturnType<typeof actual.useGameLibraryStore.getState>) => unknown) => selector ? selector(actual.useGameLibraryStore.getState()) : actual.useGameLibraryStore.getState(), actual.useGameLibraryStore) };
});
afterEach(() => useGameLibraryStore.setState({ library: null, error: null, pendingAction: null }));
describe("native launch library", () => {
  it("shows a running player with missing details as status rather than a failed join", () => {
    useGameLibraryStore.setState({ library: { entries: [], current: null, warning: null, status: "Roblox is running. Server details have not been detected yet.", notify_joins: false } });
    const html=renderToStaticMarkup(<GameLibraryPanel />);
    expect(html).toContain('role="status"');
    expect(html).toContain("Roblox is running.");
    expect(html).not.toContain('role="alert"');
    expect(html).not.toContain("A running game was not detected within a minute");
  });
  it("offers native safe launch and shortcuts without claiming to manage Roblox updates", () => {
    useGameLibraryStore.setState({ library: { entries: [{ place_id:"1818",name:"Crossroads",job_id:null,last_played:null,favourite:true,client:"standard" }],current:null,warning:null,notify_joins:false } });
    const html=renderToStaticMarkup(<GameLibraryPanel />);
    expect(html).toContain("Safe launch (no FastFlags)");
    expect(html).toContain("Create game shortcut");
    expect(html).not.toContain("Install Roblox update");
  });
});
