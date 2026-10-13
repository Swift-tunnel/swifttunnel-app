import { describe, expect, it } from "vitest";
import { gameLibraryEntries, gameLinkClient, gameSessionDescription, gameShareUrl, parsePlaceInput } from "./robloxGames";
import type { GameRouteStatus, RobloxGameSession, RobloxGameEntry } from "./types";

const session: RobloxGameSession = { place_id: "1818", job_id: "550e8400-e29b-41d4-a716-446655440000", ip: "128.116.47.33", client: "standard", fresh_join: true, observed_at: 1 };
const route: GameRouteStatus = { game_location: "Mumbai", game_server_ip: session.ip, relay: "mumbai-01", estimated_path_ms: 26, bypassed: false };
describe("game library", () => {
  it("groups lobby and gameplay places, retains favourites, and limits recents to four experiences", () => {
    const entries: RobloxGameEntry[] = Array.from({ length: 6 }, (_, i) => ({
      place_id: `${100 + i}`, universe_id: `${200 + i}`, client: "standard",
      name: `Game ${i}`, job_id: null, last_played: 10 - i, favourite: true,
    }));
    entries.push({ ...entries[0], place_id: "999", last_played: 20, job_id: session.job_id, favourite: false });
    const recent = gameLibraryEntries(entries, "all", "");
    expect(recent).toHaveLength(4);
    expect(recent[0]).toMatchObject({ place_id: "999", job_id: session.job_id, favourite: true });
    expect(gameLibraryEntries(entries, "favourites", "")).toHaveLength(6);
    expect(gameLibraryEntries(entries, "all", "Game 5")).toHaveLength(1);
    expect(entries[0].place_id).toBe("100"); // No sorting/mutation of stored history.
  });
  it("keeps different experiences with the same name and separate installed clients", () => {
    const entry: RobloxGameEntry = { place_id: "100", universe_id: "200", client: "standard", name: "Same title", job_id: null, last_played: 10, favourite: false };
    expect(gameLibraryEntries([entry, { ...entry, universe_id: "201", place_id: "101" }, { ...entry, client: "vng" }], "all", "")).toHaveLength(3);
    expect(gameLibraryEntries([{ ...entry, universe_id: null }, { ...entry, universe_id: null, place_id: "101" }], "all", "")).toHaveLength(2);
  });
  it("accepts official game links and rejects hostile hosts, scripts and unsafe IDs", () => {
    expect(parsePlaceInput(" https://www.roblox.com/games/1818/Crossroads ")).toBe("1818");
    expect(parsePlaceInput("1818")).toBe("1818");
    for (const value of ["javascript:alert(1)", "https://www.roblox.com.evil/games/1818", "https://evil@www.roblox.com/games/1818", "0", "01", "1818&accessCode=secret", "9223372036854775808"]) expect(parsePlaceInput(value)).toBeNull();
  });
  it("never presents another server's location or ping as the current game", () => {
    expect(gameSessionDescription(session, { ...route, game_server_ip: "128.116.46.33" })).not.toContain("Mumbai");
    expect(gameSessionDescription(session, { ...route, game_server_ip: null })).not.toContain("26");
    expect(gameSessionDescription(session, route)).toBe("Roblox Mumbai · ~26 ms");
    expect(gameSessionDescription(session, { ...route, estimated_path_ms: NaN })).not.toContain("ms");
    expect(gameSessionDescription(session, { ...route, bypassed: true })).toBe("Roblox Mumbai · Direct connection");
  });
  it("builds join links without authentication or private-server credentials", () => {
    const link = new URL(gameShareUrl("1818", session.job_id));
    expect(link.host).toBe("www.roblox.com");
    expect([...link.searchParams.keys()]).toEqual(["placeId", "gameInstanceId"]);
  });
  it("recognises official VNG game links without accepting lookalike hosts", () => {
    expect(parsePlaceInput("https://www.robloxapp.vnggames.com/games/1818/Crossroads")).toBe("1818");
    expect(gameLinkClient("https://robloxapp.vnggames.com/games/1818")).toBe("vng");
    expect(gameLinkClient("https://www.roblox.com/games/1818")).toBe("standard");
    expect(gameLinkClient("1818")).toBeNull();
    for (const input of ["https://robloxapp.vnggames.com.evil/games/1818", "http://robloxapp.vnggames.com/games/1818", "https://evil@robloxapp.vnggames.com/games/1818"]) {
      expect(gameLinkClient(input)).toBeNull();
      expect(parsePlaceInput(input)).toBeNull();
    }
    const link = new URL(gameShareUrl("1818", session.job_id, "vng"));
    expect(link.hostname).toBe("www.robloxapp.vnggames.com");
    expect([...link.searchParams.keys()]).toEqual(["placeId", "gameInstanceId"]);
  });
});
