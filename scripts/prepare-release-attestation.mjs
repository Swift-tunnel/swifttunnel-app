import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Use this run's final local outputs, never an arbitrary download from an old release.
export function stageReleaseArtifacts({ repoRoot, runnerTemp, version }) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
    throw new Error("Invalid release version");
  }
  if (!runnerTemp) throw new Error("RUNNER_TEMP is required");
  const files = [];
  const addMsi = (directory, signed) => {
    const matches = fs.readdirSync(directory).filter((name) => name.endsWith(".msi"));
    if (matches.length !== 1) throw new Error(`Expected one MSI in ${directory}`);
    const msi = path.join(directory, matches[0]);
    files.push(msi);
    if (signed) files.push(`${msi}.sig`);
  };
  for (const [target, arch, suffix] of [
    ["x86_64-pc-windows-msvc", "x64", ""],
    ["aarch64-pc-windows-msvc", "arm64", "-arm64"],
  ]) {
    addMsi(path.join(repoRoot, "target", target, "release/bundle/msi"), true);
    addMsi(path.join(repoRoot, "swifttunnel-lite/target-msi", arch), false);
    for (const prefix of ["SwiftTunnel-Setup", "SwiftTunnelLite-Setup", "SwiftTunnel-Offline-Setup"]) {
      files.push(path.join(repoRoot, `${prefix}-${version}${suffix}.exe`));
    }
  }
  for (const name of ["latest.json", "swifttunnel-update-manifest.json", "swifttunnel-update-manifest.sig"]) {
    files.push(path.join(runnerTemp, "swifttunnel_manifest", name));
  }
  const names = new Set();
  for (const file of files) {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size === 0) throw new Error(`Missing or empty release file: ${file}`);
    const name = path.basename(file);
    if (names.has(name)) throw new Error(`Duplicate release filename: ${name}`);
    names.add(name);
  }
  const directory = fs.mkdtempSync(path.join(runnerTemp, "release-provenance-"));
  for (const file of files) fs.copyFileSync(file, path.join(directory, path.basename(file)));
  // Forward slashes work for the attestation action's glob on Windows too.
  return directory.replaceAll("\\", "/");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(stageReleaseArtifacts({
    repoRoot: process.cwd(), runnerTemp: process.env.RUNNER_TEMP, version: process.env.RELEASE_VERSION,
  }));
}
