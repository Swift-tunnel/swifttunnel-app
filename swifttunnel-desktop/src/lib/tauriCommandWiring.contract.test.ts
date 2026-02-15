import { describe, expect, it } from "vitest";
import commandsTs from "./commands.ts?raw";
import backendLibRs from "../../src-tauri/src/lib.rs?raw";

function extractInvokedCommands(source: string): string[] {
  const out = new Set<string>();
  const re = /\binvoke(?:<[^>]*>)?\s*\(\s*["']([^"']+)["']/g;
  let m: RegExpExecArray | null = null;
  while ((m = re.exec(source)) !== null) {
    out.add(m[1]!);
  }
  return [...out].sort();
}

function extractRegisteredCommands(source: string): string[] {
  const out = new Set<string>();
  const re = /\bcommands::[a-z_]+::([a-zA-Z0-9_]+)\b/g;
  let m: RegExpExecArray | null = null;
  while ((m = re.exec(source)) !== null) {
    out.add(m[1]!);
  }
  return [...out].sort();
}

describe("Tauri command wiring", () => {
  it("all frontend-invoked commands are registered in src-tauri invoke_handler", () => {
    const invoked = extractInvokedCommands(commandsTs);
    const registered = new Set(extractRegisteredCommands(backendLibRs));

    const missing = invoked.filter((cmd) => !registered.has(cmd));
    expect(missing, `Missing backend Tauri commands: ${missing.join(", ")}`).toEqual([]);
  });
});
