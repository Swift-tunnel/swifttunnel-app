// Build the standalone SwiftTunnel Lite installer.
//
// Lite also ships inside the full app's MSI. This is the other route, for
// someone on a machine that cannot comfortably run the full client and should
// not have to install it to get the small one.
//
// Uses the WiX 3 toolset Tauri already downloads for the main bundle rather
// than asking for a second one, so CI needs no extra setup as long as this
// runs after the app has been built at least once.
//
//   node scripts/build-msi.mjs [--target <triple>]

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { liteMsiInputs } from "../../scripts/msi-build-paths.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const crate = resolve(here, "..");
const repo = resolve(crate, "..");

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

const triple = flag("--target") ?? process.env.TAURI_ENV_TARGET_TRIPLE ?? "";
const targetDir = JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
  cwd: repo, encoding: "utf8", windowsHide: true, maxBuffer: 64 * 1024 * 1024,
})).target_directory;
const host = triple ? triple : execFileSync("rustc", ["-vV"], {
  encoding: "utf8", windowsHide: true,
}).match(/^host: (.+)$/m)?.[1]?.trim();
const { arch, litePath, wixDir } = liteMsiInputs(targetDir, triple, host);
const wixArch = arch === "arm64" ? "arm64" : "x64";

// The version is the crate's, so the installer and the About row cannot
// disagree about what is installed.
const version = readFileSync(join(crate, "Cargo.toml"), "utf8")
  .match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version) throw new Error("could not read the Lite version from Cargo.toml");

// ── Inputs ─────────────────────────────────────────────────────────────────

// The driver package Lite ships beside itself, in the layout core searches
// for. Taken from the desktop crate's resources so there is one copy of it in
// the repo rather than two that can drift.
const driverDir = join(
  repo,
  "swifttunnel-desktop",
  "src-tauri",
  "resources",
  "drivers",
  "winpkfilter",
  arch,
  "win10",
);

const iconPath = join(crate, "resources", "icon.ico");

for (const [label, path] of [
  ["Lite binary", litePath],
  ["driver package", driverDir],
  ["icon", iconPath],
]) {
  if (!existsSync(path)) {
    throw new Error(`${label} not found at ${path}`);
  }
}

// ── The toolset ────────────────────────────────────────────────────────────

const candle = join(wixDir, "candle.exe");
const light = join(wixDir, "light.exe");
if (!existsSync(candle) || !existsSync(light)) {
  throw new Error(
    `WiX 3 not found in ${wixDir}. Run a \`tauri build\` first: it downloads the toolset this reuses.`,
  );
}

// ── Build ──────────────────────────────────────────────────────────────────

// Resolve the freshly built action DLL from Cargo, including external target dirs.
const actionOutput = execFileSync("cargo", ["build", "-p", "swifttunnel-msi-actions", "--release", "--target", triple || host, "--message-format=json-render-diagnostics"], {
  cwd: repo, encoding: "utf8", windowsHide: true, maxBuffer: 32 * 1024 * 1024,
});
const actionDlls = actionOutput.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line))
  .filter(record => record.reason === "compiler-artifact" && record.target?.name === "swifttunnel_msi_actions")
  .flatMap(record => record.filenames.filter(name => name.endsWith(".dll")));
if (actionDlls.length !== 1) throw new Error("Cargo did not identify one MSI action DLL");
const actionDll = actionDlls[0];
for (const binary of [litePath, actionDll]) {
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File",
    join(repo, "scripts", "check-vc-runtime.ps1"), "-Binary", binary],
    { cwd: repo, stdio: "inherit", windowsHide: true });
}
const pe = readFileSync(actionDll);
if (pe.readUInt16LE(pe.readUInt32LE(0x3c) + 4) !== (arch === "arm64" ? 0xaa64 : 0x8664)) {
  throw new Error("MSI action DLL architecture mismatch");
}

const out = join(crate, "target-msi", arch);
mkdirSync(out, { recursive: true });

const wixobj = join(out, "product.wixobj");
const msi = join(out, `SwiftTunnelLite_${version}_${arch}_en-US.msi`);

console.log(`==> candle (${wixArch})`);
execFileSync(
  candle,
  [
    "-arch",
    wixArch,
    `-dVersion=${version}`,
    `-dMsiActionsPath=${actionDll}`,
    `-dLitePath=${litePath}`,
    `-dDriverDir=${driverDir}`,
    `-dDriverArch=${arch}`,
    `-dIconPath=${iconPath}`,
    "-out",
    wixobj,
    join(crate, "wix", "product.wxs"),
  ],
  { stdio: "inherit" },
);

// Compile the same UI fragment the Desktop bundle uses.
const uiObject = join(out, "SwiftSetupUI.wixobj");
execFileSync(candle, ["-arch", wixArch, "-out", uiObject, join(repo, "installer", "SwiftSetupUI.wxs")], { stdio: "inherit", windowsHide: true });

console.log("==> light");
execFileSync(
  light,
  [
    "-ext",
    "WixUIExtension",
    // ICE61 fires on AllowDowngrades, which is deliberate: a downgrade here is
    // someone reinstalling an older Lite on purpose and should not be blocked.
    "-sice:ICE61",
    "-out",
    msi,
    wixobj,
    uiObject,
  ],
  { stdio: "inherit" },
);

console.log(`==> wrote ${msi}`);
