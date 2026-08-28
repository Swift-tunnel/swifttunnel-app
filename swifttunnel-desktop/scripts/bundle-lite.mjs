// Build SwiftTunnel Lite and stage it where the installer can find it.
//
// Lite is a separate crate on purpose: Tauri's WiX bundler installs every bin
// target of the package it bundles, so a second binary inside src-tauri would
// be shipped whether or not anyone wanted it, and `required-features` is no
// defence. Being its own crate means it has to be built and copied here
// deliberately, which is what this does.
//
// Run from `beforeBuildCommand`, so a plain `tauri build` produces an installer
// with Lite in it and nobody has to remember a second command. The target
// triple comes from Tauri's own environment, so an ARM64 bundle gets an ARM64
// Lite rather than an x64 one that will not run on it.

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const desktop = resolve(here, "..");
const repo = resolve(desktop, "..");
const stage = join(desktop, "src-tauri", "resources", "lite");

// Set by Tauri for beforeBuildCommand. Empty for a host build.
const triple = process.env.TAURI_ENV_TARGET_TRIPLE ?? "";

const args = ["build", "-p", "swifttunnel-lite", "--release"];
if (triple) {
  args.push("--target", triple);
}

console.log(`==> cargo ${args.join(" ")}`);
execFileSync("cargo", args, { cwd: repo, stdio: "inherit" });

const built = triple
  ? join(repo, "target", triple, "release", "swifttunnel-lite.exe")
  : join(repo, "target", "release", "swifttunnel-lite.exe");

// A stale copy from a previous build would ship silently, so the freshly built
// one has to actually be there.
const size = statSync(built).size;
if (size < 1_000_000) {
  throw new Error(`${built} is only ${size} bytes; that is not a real build`);
}

mkdirSync(stage, { recursive: true });
const out = join(stage, "swifttunnel-lite.exe");
copyFileSync(built, out);
console.log(`==> staged ${out} (${(size / 1024 / 1024).toFixed(1)} MB)`);
