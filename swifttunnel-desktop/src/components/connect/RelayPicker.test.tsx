import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { RelayPicker } from "./RelayPicker";
import type { ReferenceEstimate, ServerInfo } from "../../lib/types";

it("renders a single ms value before connecting and keeps the target in the tooltip", () => {
  const previews: ReferenceEstimate[] = [{ relay: "mumbai-01", address: "1.2.3.4:51821",
    relay_ms: 20, second_leg_ms: 2, estimated_game_ms: 22, target: "128.116.47.3",
    location: "Mumbai", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 }];
  const html = renderToStaticMarkup(<RelayPicker
    region={{ id: "mumbai", name: "Mumbai", description: "India", country_code: "IN", servers: ["mumbai-01"] }}
    servers={[{ region: "mumbai-01", ip: "1.2.3.4", relay_port: 51821, relay_available: true } as ServerInfo]}
    latencies={new Map([["relay:mumbai-01", 20]])} previews={previews}
    value={null} disabled={false} onChange={() => {}} />);
  expect(html).toContain("~22 ms");
  expect(html).not.toContain("20 ms");
  expect(html).not.toContain("ms game");
  expect(html).not.toContain("ms relay");
  expect(html).toContain("Estimate to Mumbai Roblox datacenter");
  expect(html).not.toContain("shared by every relay");
  expect(html).not.toContain("Game estimates appear when connected");
});

it("keeps Singapore's datacenter estimate when the active game is in Mumbai", () => {
  const previews: ReferenceEstimate[] = [{ relay: "singapore-01", address: "1.2.3.5:51821",
    relay_ms: 40, second_leg_ms: 2, estimated_game_ms: 42, target: "128.116.46.3",
    location: "Singapore", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 }];
  const html = renderToStaticMarkup(<RelayPicker
    region={{ id: "singapore", name: "Singapore", description: "Singapore", country_code: "SG", servers: ["singapore-01"] }}
    servers={[{ region: "singapore-01", ip: "1.2.3.5", relay_port: 51821, relay_available: true } as ServerInfo]}
    latencies={new Map([["relay:singapore-01", 40]])} previews={previews}
    gameRoute={{ game_location: "Mumbai", relay: "singapore-01", estimated_path_ms: 99, bypassed: false,
      relay_estimates: [{ relay: "singapore-01", address: "1.2.3.5:51821", relay_ms: 40, second_leg_ms: 59, estimated_game_ms: 99 }] }}
    value={null} disabled={false} onChange={() => {}} />);
  expect(html).toContain("~42 ms");
  expect(html).not.toContain("99 ms");
  expect(html).toContain("Estimate to Singapore Roblox datacenter");
  expect(html).not.toContain("Mumbai");
});
