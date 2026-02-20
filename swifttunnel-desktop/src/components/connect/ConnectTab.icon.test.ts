import { describe, expect, it } from "vitest";
import connectTabSource from "./ConnectTab.tsx?raw";

describe("ConnectTab power button icon", () => {
  it("uses a power glyph instead of the old wifi glyph", () => {
    expect(connectTabSource).toContain('<path d="M12 2v10" />');
    expect(connectTabSource).toContain(
      '<path d="M18.36 6.64a9 9 0 1 1-12.73 0" />',
    );

    expect(connectTabSource).not.toContain(
      '<path d="M5 12.55a11 11 0 0 1 14.08 0" />',
    );
    expect(connectTabSource).not.toContain(
      '<path d="M1.42 9a16 16 0 0 1 21.16 0" />',
    );
    expect(connectTabSource).not.toContain(
      '<path d="M8.53 16.11a6 6 0 0 1 6.95 0" />',
    );
  });

  it("shows automatic split tunnel driver install status text", () => {
    expect(connectTabSource).toContain("Checking split tunnel driver");
    expect(connectTabSource).toContain(
      "Installing required split tunnel driver",
    );
  });
});
