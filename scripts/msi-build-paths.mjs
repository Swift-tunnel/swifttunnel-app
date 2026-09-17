import { join } from "node:path";

export function liteMsiInputs(targetDirectory, target, host) {
  const architecture = target || host;
  if (!["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"].includes(architecture)) {
    throw new Error(`Unsupported MSI target: ${architecture}`);
  }
  if (!targetDirectory) throw new Error("Cargo did not report a target directory");
  return {
    arch: architecture.startsWith("aarch64") ? "arm64" : "x64",
    litePath: join(targetDirectory, ...(target ? [target] : []), "release", "swifttunnel-lite.exe"),
    wixDir: join(targetDirectory, ".tauri", "WixTools314"),
  };
}
