import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { GameLibraryPanel } from "./GameLibraryPanel";
import { useGameLibraryStore } from "../../stores/gameLibraryStore";
import { useVpnStore } from "../../stores/vpnStore";

vi.mock("../../stores/gameLibraryStore", async () => {
  const actual = await vi.importActual<typeof import("../../stores/gameLibraryStore")>("../../stores/gameLibraryStore");
  // Static rendering uses Zustand's initial server snapshot. Read the test's
  // current fixture instead so this exercises the loaded and failed UI states.
  return { useGameLibraryStore: Object.assign(() => actual.useGameLibraryStore.getState(), actual.useGameLibraryStore) };
});

vi.mock("../../lib/commands", () => ({ gamesGetLibrary: vi.fn(), gamesAddFavourite: vi.fn(), gamesForget: vi.fn(), gamesJoin: vi.fn(), gamesSetFavourite: vi.fn(), gamesSetNotifications: vi.fn() }));
afterEach(() => { useGameLibraryStore.setState({ library: null, error: null, loading: false }); useVpnStore.setState({ gameRoute: null }); });
describe("game library panel", () => {
  it("shows supported rejoin actions while keeping VNG's unverified native join unavailable", () => {
    useGameLibraryStore.setState({ library: { current: null, warning: null, notify_joins: false, entries: [
      { place_id: "1818", name: "Crossroads", job_id: "550e8400-e29b-41d4-a716-446655440000", favourite: true, last_played: 20, client: "standard" },
      { place_id: "1818", name: "Crossroads VNG", job_id: "550e8400-e29b-41d4-a716-446655440000", favourite: true, last_played: 20, client: "vng" },
    ] } });
    const html = renderToStaticMarkup(<GameLibraryPanel />);
    expect(html).toContain("Crossroads");
    expect(html.match(/>Rejoin</g)).toHaveLength(1);
    expect(html.match(/>Copy link</g)).toHaveLength(1);
    expect(html).toContain("Roblox VNG");
  });
  it("keeps a failed library load visibly unavailable instead of claiming an empty history", () => {
    useGameLibraryStore.setState({ error: "The original file has been kept." });
    const html = renderToStaticMarkup(<GameLibraryPanel />);
    expect(html).toContain("The original file has been kept.");
    expect(html).not.toContain("Join a game with SwiftTunnel open");
  });
});
