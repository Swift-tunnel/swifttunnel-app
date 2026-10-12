import { describe, expect, it } from "vitest";
import { gameSessionDescription, gameShareUrl, parsePlaceInput } from "./robloxGames";
import type { GameRouteStatus, RobloxGameSession } from "./types";

const session: RobloxGameSession = { place_id: "1818", job_id: "550e8400-e29b-41d4-a716-446655440000", ip: "128.116.47.33", client: "standard", fresh_join: true, observed_at: 1 };
const route: GameRouteStatus = { game_location: "Mumbai", game_server_ip: session.ip, relay: "mumbai-01", estimated_path_ms: 26, bypassed: false };
describe("game library", () => {
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
});
