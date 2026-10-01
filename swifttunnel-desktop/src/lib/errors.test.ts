import { describe, expect, it, vi } from "vitest";
import { formatErrorMessage, reportError } from "./errors";

describe("error reporting", () => {
  it("reads Error and serialized IPC errors", () => {
    expect(formatErrorMessage(new Error("Could not reconnect"))).toBe("Could not reconnect");
    expect(formatErrorMessage({ message: "Try another region" })).toBe("Try another region");
    expect(formatErrorMessage({ error: "Server unavailable" })).toBe("Server unavailable");
  });
  it("gives a usable fallback for empty or unknown failures", () => {
    for (const value of [null, undefined, {}, "  ", { message: 42 }]) {
      expect(formatErrorMessage(value)).toBe("Something went wrong. Please try again.");
    }
  });
  it("bounds accidentally huge error payloads", () => {
    expect(formatErrorMessage("x".repeat(100_000))).toHaveLength(4099);
  });
  it("deduplicates recent failures but evicts old entries on a long-running app", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      reportError("test", "first", { dedupeKey: "bounded-test" });
      reportError("test", "first", { dedupeKey: "bounded-test" });
      expect(warn).toHaveBeenCalledTimes(1);
      for (let i = 0; i < 256; i++) reportError("test", `failure ${i}`, { dedupeKey: "bounded-test" });
      reportError("test", "first", { dedupeKey: "bounded-test" });
      expect(warn).toHaveBeenCalledTimes(258);
    } finally { warn.mockRestore(); }
  });
});
