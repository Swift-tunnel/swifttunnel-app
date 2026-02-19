import { describe, expect, it } from "vitest";
import { formatConnectedServerLabel } from "./connectedServer";
import type { ServerInfo } from "./types";

const SERVERS: ServerInfo[] = [
  {
    region: "mumbai",
    name: "mumbai-02",
    country_code: "IN",
    ip: "1.2.3.4",
    port: 51821,
  },
  {
    region: "singapore",
    name: "singapore-01",
    country_code: "SG",
    ip: "8.8.8.8",
    port: 51821,
  },
];

describe("formatConnectedServerLabel", () => {
  it("shows matched server name with exact endpoint", () => {
    const label = formatConnectedServerLabel("1.2.3.4:51821", SERVERS, "mumbai");
    expect(label).toBe("mumbai-02 (1.2.3.4:51821)");
  });

  it("falls back to raw endpoint when server is unknown", () => {
    const label = formatConnectedServerLabel("9.9.9.9:51821", SERVERS, "mumbai");
    expect(label).toBe("9.9.9.9:51821");
  });

  it("falls back to region when endpoint is missing", () => {
    const label = formatConnectedServerLabel(null, SERVERS, "mumbai");
    expect(label).toBe("mumbai");
  });
});
