import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { liteMsiInputs } from "./msi-build-paths.mjs";

test("Lite packaging follows a target directory outside the checkout", () => {
  const inputs = liteMsiInputs("C:/cargo-target/swifttunnel", "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc");
  assert.equal(inputs.litePath, join("C:/cargo-target/swifttunnel", "x86_64-pc-windows-msvc", "release", "swifttunnel-lite.exe"));
  assert.equal(inputs.wixDir, join("C:/cargo-target/swifttunnel", ".tauri", "WixTools314"));
  assert.equal(inputs.arch, "x64");
});
test("a native ARM64 build does not package the x64 driver", () => {
  const inputs = liteMsiInputs("external-target", "", "aarch64-pc-windows-msvc");
  assert.equal(inputs.arch, "arm64");
  assert.equal(inputs.litePath, join("external-target", "release", "swifttunnel-lite.exe"));
});
test("unsupported targets fail instead of silently selecting x64", () => {
  assert.throws(() => liteMsiInputs("target", "i686-pc-windows-msvc", "x86_64-pc-windows-msvc"), /Unsupported/);
});
