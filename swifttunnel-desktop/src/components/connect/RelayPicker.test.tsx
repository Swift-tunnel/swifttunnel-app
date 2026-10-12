import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { RelayPicker } from "./RelayPicker";
import type { ReferenceEstimate, ServerInfo } from "../../lib/types";

it("renders estimated game ping before a tunnel or game exists and names the reference", () => {
  const previews: ReferenceEstimate[] = [{ relay: "mumbai-01", address: "1.2.3.4:51821",
    relay_ms: 20, second_leg_ms: 2, estimated_game_ms: 22, target: "128.116.47.3",
    location: "Mumbai", valid_for_ms: 45_000, expiresAt: performance.now() + 45_000 }];
  const html = renderToStaticMarkup(<RelayPicker
    region={{ id: "mumbai", name: "Mumbai", description: "India", country_code: "IN", servers: ["mumbai-01"] }}
    servers={[{ region: "mumbai-01", ip: "1.2.3.4", relay_port: 51821, relay_available: true } as ServerInfo]}
    latencies={new Map([["relay:mumbai-01", 20]])} previews={previews}
    value={null} disabled={false} onChange={() => {}} />);
  expect(html).toContain("~22 ms game / 20 ms relay");
  expect(html).toContain("Mumbai Roblox reference datacenter");
  expect(html).not.toContain("Game estimates appear when connected");
});
