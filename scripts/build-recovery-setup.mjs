import { spawnSync } from "node:child_process";
import { copyFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export function setupPlan({ target, flavor, version, msi }) {
  if (!["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"].includes(target)) {
    throw new Error("Unsupported recovery setup target");
  }
  if (!["desktop", "lite"].includes(flavor)) throw new Error("Unknown setup product");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
    throw new Error("Invalid release version");
  }
  if (!msi || path.extname(msi).toLowerCase() !== ".msi") throw new Error("Expected an MSI payload");
  const prefix = flavor === "lite" ? "SwiftTunnelLite" : "SwiftTunnel";
  const suffix = target.startsWith("aarch64") ? "-arm64" : "";
  return {
    output: `${prefix}-Setup-${version}${suffix}.exe`,
    payloadName: `${prefix}-Installer.msi`,
    payload: path.resolve(msi),
    args: ["build", "-p", "swifttunnel-setup", "--bin", "SwiftTunnel-Setup",
      "--release", "--target", target, "--message-format=json-render-diagnostics"],
  };
}

export function emittedSetup(result) {
  // Never copy a stale binary after a failed build, even if Cargo emitted an
  // earlier artifact record or an executable remains from the other product.
  if (result.error || result.status !== 0) throw new Error("Recovery setup build failed");
  const artifacts = (result.stdout ?? "").split(/\r?\n/).filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((record) => record.reason === "compiler-artifact"
      && record.target?.name === "SwiftTunnel-Setup"
      && record.target?.kind?.includes("bin") && record.executable);
  if (artifacts.length !== 1) throw new Error("Cargo did not identify one recovery executable");
  return artifacts[0].executable;
}

export function buildRecoverySetup(options, io = {
  build: (args, env) => spawnSync("cargo", args, {
    env, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
    windowsHide: true, maxBuffer: 32 * 1024 * 1024,
  }),
  stat: statSync,
  copy: copyFileSync,
}) {
  const plan = setupPlan(options);
  const payload = io.stat(plan.payload);
  if (!payload.isFile() || payload.size <= 1_000_000) throw new Error("MSI payload is incomplete");
  const result = io.build(plan.args, {
    ...process.env,
    SWIFTTUNNEL_SETUP_MSI: plan.payload,
    SWIFTTUNNEL_SETUP_NAME: plan.payloadName,
  });
  const executable = emittedSetup(result);
  const built = io.stat(executable);
  if (!built.isFile() || built.size < payload.size) throw new Error("Recovery executable lacks its payload");
  io.copy(executable, plan.output);
  return plan.output;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({ options: {
      target: { type: "string" }, flavor: { type: "string" },
      version: { type: "string" }, msi: { type: "string" },
    } });
    console.log(buildRecoverySetup(values));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
