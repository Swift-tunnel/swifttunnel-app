import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
import { ConnectTab } from "./ConnectTab";
import { useServerStore } from "../../stores/serverStore";
import type { ServerRegion, ServerInfo } from "../../lib/types";

vi.mock("../../stores/serverStore", async () => {
  const actual = await vi.importActual<typeof import("../../stores/serverStore")>("../../stores/serverStore");
  return { useServerStore: Object.assign(
    (selector: (state: ReturnType<typeof actual.useServerStore.getState>) => unknown) => selector(actual.useServerStore.getState()),
    actual.useServerStore,
  ) };
});

const regions: ServerRegion[] = ["Singapore", "Mumbai", "Tokyo", "Jakarta"].map(name => ({
  id: name.toLowerCase(), name, description: "", country_code: "", servers: [`${name.toLowerCase()}-01`],
}));
beforeEach(() => useServerStore.setState({ regions, servers: [], previews: [], latencies: new Map(), isLoading: false, error: null }));

function renderedOrder() {
  const html = renderToStaticMarkup(<ConnectTab />);
  const start = html.indexOf('id="connect-regions"');
  const section = html.slice(start, html.indexOf("</section>", start));
  return regions.map(region => ({ name: region.name, at: section.indexOf(`>${region.name}</span>`) }))
    .sort((a, b) => a.at - b.at).map(row => {
      expect(row.at).toBeGreaterThan(-1);
      return row.name;
    });
}

it("sorts measured regions lowest first, moves missing pings last, and updates with new readings", () => {
  useServerStore.setState({ latencies: new Map([["mumbai", 18], ["tokyo", 72], ["jakarta", 0]]) });
  expect(renderedOrder()).toEqual(["Jakarta", "Mumbai", "Tokyo", "Singapore"]);
  useServerStore.setState({ latencies: new Map([["singapore", 5], ["mumbai", 80], ["tokyo", 25], ["jakarta", null]]) });
  expect(renderedOrder()).toEqual(["Singapore", "Tokyo", "Mumbai", "Jakarta"]);
  useServerStore.setState({ latencies: new Map([["singapore", 25], ["mumbai", 25]]) });
  expect(renderedOrder()).toEqual(["Singapore", "Mumbai", "Tokyo", "Jakarta"]);
  expect(useServerStore.getState().regions.map(region => region.name)).toEqual(["Singapore", "Mumbai", "Tokyo", "Jakarta"]);
});

it("orders by the displayed game estimate when available and falls back when it expires", () => {
  const server: ServerInfo = { region: "singapore-01", name: "Singapore 01", country_code: "SG", ip: "1.2.3.4", port: 51820, relay_port: 51821, relay_available: true };
  const preview = { relay: server.region, address: "1.2.3.4:51821", relay_ms: 5, second_leg_ms: 35,
    estimated_game_ms: 40, location: "Singapore", target: "128.116.1.3", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 };
  useServerStore.setState({ servers: [server], latencies: new Map([["singapore", 5], ["mumbai", 18]]), previews: [preview] });
  expect(renderedOrder()).toEqual(["Mumbai", "Singapore", "Tokyo", "Jakarta"]);
  useServerStore.setState({ previews: [{ ...preview, expiresAt: 0 }] });
  expect(renderedOrder()).toEqual(["Singapore", "Mumbai", "Tokyo", "Jakarta"]);
});
