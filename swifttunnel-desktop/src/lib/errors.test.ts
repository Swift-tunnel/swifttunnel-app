import { describe, expect, it, vi } from "vitest";
import { APP_FAULT_MESSAGE, formatErrorMessage, reportError } from "./errors";

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
  it("never shows a player the text of a fault in the app's own script", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      let fault: unknown;
      try {
        (undefined as unknown as { entries: unknown[] }).entries.length;
      } catch (error) {
        fault = error;
      }
      expect(formatErrorMessage(fault)).toBe(APP_FAULT_MESSAGE);
      expect(formatErrorMessage(new ReferenceError("games is not defined"))).toBe(APP_FAULT_MESSAGE);
      // The real text stays available to a developer.
      expect(warn).toHaveBeenCalledTimes(2);
      // A network failure is a TypeError too, and its text is worth showing.
      expect(formatErrorMessage(new TypeError("Failed to fetch"))).toBe("Failed to fetch");
      // The same words from the backend, or in a plain Error, are a message.
      expect(formatErrorMessage("driver is not defined for this adapter")).toBe(
        "driver is not defined for this adapter",
      );
      expect(formatErrorMessage(new Error("Relay is not a function of region"))).toBe(
        "Relay is not a function of region",
      );
    } finally { warn.mockRestore(); }
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
