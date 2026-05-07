import { describe, expect, it } from "vitest";
import { formatBannedAt } from "./BannedScreen";

describe("BannedScreen", () => {
  it("formats valid ban timestamps", () => {
    expect(formatBannedAt("2026-05-07T13:55:59.000Z")).toBeTruthy();
  });

  it("hides malformed ban timestamps", () => {
    expect(formatBannedAt("null")).toBeNull();
    expect(formatBannedAt("not-a-date")).toBeNull();
    expect(formatBannedAt(null)).toBeNull();
  });
});
