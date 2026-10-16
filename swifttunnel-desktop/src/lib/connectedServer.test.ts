import { describe, expect, it } from "vitest";
import { formatConnectedServerLabel } from "./connectedServer";
import type { ServerInfo } from "./types";

const SERVERS: ServerInfo[] = [
  {
    region: "mumbai-02",
    name: "Mumbai",
    country_code: "IN",
    ip: "1.2.3.4",
    port: 51821,
    relay_available: true,
    relay_port: 51821,
  },
  {
    region: "singapore-01",
    name: "Singapore",
    country_code: "SG",
    ip: "8.8.8.8",
    port: 51821,
    relay_available: true,
    relay_port: 51821,
  },
];

describe("formatConnectedServerLabel", () => {
  it("shows the actual relay number when API names only contain the city", () => {
    const label = formatConnectedServerLabel("1.2.3.4:51821", SERVERS, "mumbai");
    expect(label).toBe("Mumbai 02");
    expect(formatConnectedServerLabel("1.2.3.4:51821", [{ ...SERVERS[0], region: "mumbai-05" }], "mumbai-05")).toBe("Mumbai 05");
  });

  it("falls back to region when server is unknown", () => {
    const label = formatConnectedServerLabel("9.9.9.9:51821", SERVERS, "mumbai");
    expect(label).toBe("Mumbai");
  });

  it("falls back to region when endpoint is missing", () => {
    const label = formatConnectedServerLabel(null, SERVERS, "mumbai");
    expect(label).toBe("Mumbai");
  });

  it("uses the connected endpoint rather than a different selected relay", () => {
    const peers = [SERVERS[0], { ...SERVERS[0], region: "mumbai-05", ip: "5.6.7.8" }];
    expect(formatConnectedServerLabel("5.6.7.8:51821", peers, "mumbai-02")).toBe("Mumbai 05");
  });

  it("matches the relay port when a host has multiple relay nodes", () => {
    const peers = [
      { ...SERVERS[0], region: "mumbai-01", port: 51820, relay_port: 51821 },
      { ...SERVERS[0], region: "mumbai-05", port: 51820, relay_port: 51822 },
    ];
    expect(formatConnectedServerLabel("1.2.3.4:51822", peers, "mumbai")).toBe("Mumbai 05");
    expect(formatConnectedServerLabel("1.2.3.4:59999", peers, "custom-relay")).toBe("Custom Relay");
    expect(formatConnectedServerLabel("1.2.3.4", peers, "mumbai")).toBe("Mumbai");
  });

  it("keeps region identity for a node hosted in a different city", () => {
    expect(formatConnectedServerLabel("1.2.3.4:51821", [{ ...SERVERS[0], region: "mumbai-04", name: "Chennai" }], "mumbai-04")).toBe("Mumbai 04");
  });

  it("formats an actual relay ID even before the server list loads", () => {
    expect(formatConnectedServerLabel(null, [], "mumbai-05")).toBe("Mumbai 05");
    expect(formatConnectedServerLabel(null, [], "us-east-02")).toBe("US East 02");
    expect(formatConnectedServerLabel(null, [], null)).toBe("Unknown");
  });

  it("supports older lists with a numbered server name", () => {
    expect(formatConnectedServerLabel("1.2.3.4:51821", [{ ...SERVERS[0], region: "mumbai", name: "mumbai-02" }], "mumbai")).toBe("Mumbai 02");
  });
});
