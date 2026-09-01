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
// Lite is a second client of the same product and reports its own crate
// version to the API. Left out of this check it drifted, and the version gate
// then refused the newest build in the product as too old to connect.
const litePath = path.join(repoRoot, "swifttunnel-lite", "Cargo.toml");

function readCargoVersion(file = cargoPath) {
  const cargoToml = fs.readFileSync(file, "utf8");
  const match = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error(`Could not read version from ${file}`);
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
const liteVersion = readCargoVersion(litePath);

if (cargoVersion !== tauriVersion) {
  throw new Error(
    `Desktop version mismatch: Cargo.toml=${cargoVersion} tauri.conf.json=${tauriVersion}`,
  );
}

if (liteVersion !== cargoVersion) {
  throw new Error(
    `Lite version mismatch: swifttunnel-lite/Cargo.toml=${liteVersion} desktop=${cargoVersion}. ` +
      `Lite reports its crate version to the API, so a stale one here is refused by the client version gate.`,
  );
}

if (expectedVersion && cargoVersion !== expectedVersion) {
  throw new Error(
    `Desktop version mismatch: expected=${expectedVersion} actual=${cargoVersion}`,
  );
}

console.log(`Desktop and Lite versions are in sync at ${cargoVersion}`);
