import { describe, expect, test } from "vitest";
import type { ServerRegion } from "./types";
import { findRegionForVpnRegion } from "./regionMatch";

function makeRegions(): ServerRegion[] {
  return [
    {
      id: "singapore",
      name: "Singapore",
      description: "",
      country_code: "SG",
      servers: ["singapore", "singapore-02"],
    },
    {
      id: "america",
      name: "America",
      description: "",
      country_code: "US",
      servers: ["america-01", "america-02"],
    },
  ];
}

describe("findRegionForVpnRegion", () => {
  test("matches by region id", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "singapore")?.id).toBe("singapore");
  });

  test("matches by server id (auto-routing)", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "america-01")?.id).toBe("america");
  });

  test("matches by display name", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "Singapore")?.id).toBe("singapore");
  });

  test("is case-insensitive", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "AMERICA-02")?.id).toBe("america");
  });

  test("returns undefined when it cannot match", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "does-not-exist")).toBeUndefined();
  });
});

