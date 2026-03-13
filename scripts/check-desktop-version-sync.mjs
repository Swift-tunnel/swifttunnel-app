import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const cargoPath = path.join(
  repoRoot,
  "swifttunnel-desktop",
  "src-tauri",
  "Cargo.toml",
);
const tauriPath = path.join(
  repoRoot,
  "swifttunnel-desktop",
  "src-tauri",
  "tauri.conf.json",
);

function readCargoVersion() {
  const cargoToml = fs.readFileSync(cargoPath, "utf8");
  const match = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error(`Could not read version from ${cargoPath}`);
  }
  return match[1].trim();
}

function readTauriVersion() {
  const tauriConfig = JSON.parse(fs.readFileSync(tauriPath, "utf8"));
  if (!tauriConfig.version || typeof tauriConfig.version !== "string") {
    throw new Error(`Could not read version from ${tauriPath}`);
  }
  return tauriConfig.version.trim();
}

const expectedVersion = process.argv[2]?.trim();
const cargoVersion = readCargoVersion();
const tauriVersion = readTauriVersion();

if (cargoVersion !== tauriVersion) {
  throw new Error(
    `Desktop version mismatch: Cargo.toml=${cargoVersion} tauri.conf.json=${tauriVersion}`,
  );
}

if (expectedVersion && cargoVersion !== expectedVersion) {
  throw new Error(
    `Desktop version mismatch: expected=${expectedVersion} actual=${cargoVersion}`,
  );
}

console.log(`Desktop versions are in sync at ${cargoVersion}`);
