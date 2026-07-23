import { describe, expect, test } from "vitest";
import type { ServerRegion } from "./types";
import { findRegionForVpnRegion, resolveValidRegion } from "./regionMatch";

function makeRegions(): ServerRegion[] {
  return [
    {
      id: "singapore",
      name: "Singapore",
      description: "",
      country_code: "SG",
      servers: ["singapore", "singapore-02", "singapore-03", "singapore-06"],
    },
    {
      id: "us-east",
      name: "US East",
      description: "",
      country_code: "US",
      servers: ["us-east-nj"],
    },
    {
      id: "us-west",
      name: "US West",
      description: "",
      country_code: "US",
      servers: ["us-west-la"],
    },
    {
      id: "us-central",
      name: "US Central",
      description: "",
      country_code: "US",
      servers: ["us-central-dallas"],
    },
  ];
}

describe("findRegionForVpnRegion", () => {
  test("matches by region id", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "singapore")?.id).toBe("singapore");
    expect(findRegionForVpnRegion(regions, "us-east")?.id).toBe("us-east");
  });

  test("matches by server id (auto-routing)", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "us-east-nj")?.id).toBe("us-east");
    expect(findRegionForVpnRegion(regions, "us-west-la")?.id).toBe("us-west");
    expect(findRegionForVpnRegion(regions, "us-central-dallas")?.id).toBe(
      "us-central",
    );
    expect(findRegionForVpnRegion(regions, "singapore-02")?.id).toBe(
      "singapore",
    );
  });

  test("matches by display name", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "Singapore")?.id).toBe("singapore");
    expect(findRegionForVpnRegion(regions, "US East")?.id).toBe("us-east");
  });

  test("is case-insensitive", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "US-EAST-NJ")?.id).toBe("us-east");
    expect(findRegionForVpnRegion(regions, "SINGAPORE")?.id).toBe("singapore");
  });

  test("returns undefined when it cannot match", () => {
    const regions = makeRegions();
    expect(findRegionForVpnRegion(regions, "does-not-exist")).toBeUndefined();
  });

  test("prefix fallback matches server to region", () => {
    // "us-east-nj" -> not a region id, not in servers? Falls to prefix "us-east"
    // Actually "us-east-nj" IS in us-east's servers list, so it matches by server id.
    // Test the prefix fallback with a hypothetical server not in the list.
    const regions = makeRegions();
    // "singapore-99" is not in any server list, but prefix "singapore" matches region id
    expect(findRegionForVpnRegion(regions, "singapore-99")?.id).toBe(
      "singapore",
    );
  });
});

describe("resolveValidRegion", () => {
  test("returns null when the saved region is already valid and canonical", () => {
    const regions = makeRegions();
    expect(resolveValidRegion(regions, "singapore")).toBeNull();
    expect(resolveValidRegion(regions, "us-east")).toBeNull();
  });

  test("normalizes a legacy suffixed id to its base region", () => {
    const regions = makeRegions();
    // Saved "singapore-03" before a fleet swap → rewritten to the "singapore" id.
    expect(resolveValidRegion(regions, "singapore-03")).toBe("singapore");
    expect(resolveValidRegion(regions, "us-east-nj")).toBe("us-east");
  });

  test("falls back to the first region when the saved one is gone entirely", () => {
    const regions = makeRegions();
    // "sydney"/"brazil" no longer exist in the fleet at all.
    expect(resolveValidRegion(regions, "sydney-03")).toBe("singapore");
    expect(resolveValidRegion(regions, "brazil")).toBe("singapore");
  });

  test("falls back for an empty or null saved region", () => {
    const regions = makeRegions();
    expect(resolveValidRegion(regions, null)).toBe("singapore");
    expect(resolveValidRegion(regions, "")).toBe("singapore");
  });

  test("prefers the lowest-latency region when latencies are known", () => {
    const regions = makeRegions();
    const latencies = new Map<string, number | null>([
      ["singapore", 180],
      ["us-east", 40],
      ["us-west", 95],
      ["us-central", null],
    ]);
    expect(resolveValidRegion(regions, "sydney", latencies)).toBe("us-east");
  });

  test("returns null when there are no regions to choose from", () => {
    expect(resolveValidRegion([], "singapore")).toBeNull();
  });
});

