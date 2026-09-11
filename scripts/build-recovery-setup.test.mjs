import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildRecoverySetup, emittedSetup, setupPlan } from "./build-recovery-setup.mjs";

const artifact = { reason: "compiler-artifact", target: { name: "SwiftTunnel-Setup", kind: ["bin"] }, executable: "emitted-setup.exe" };
const result = { status: 0, stdout: JSON.stringify(artifact) };

test("each product and architecture keeps its own payload and recovery asset", () => {
  const outputs = new Set();
  for (const flavor of ["desktop", "lite"]) {
    for (const target of ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]) {
      let copied = false;
      const output = buildRecoverySetup({ flavor, target, version: "3.1.6", msi: `${flavor}.msi` }, {
        stat: () => ({ isFile: () => true, size: 2_000_000 }),
        build: (args, env) => {
          assert.equal(args[args.indexOf("--target") + 1], target);
          assert.ok(env.SWIFTTUNNEL_SETUP_MSI.endsWith(`${flavor}.msi`));
          assert.equal(env.SWIFTTUNNEL_SETUP_NAME, flavor === "lite" ? "SwiftTunnelLite-Installer.msi" : "SwiftTunnel-Installer.msi");
          return result;
        },
        copy: (source, destination) => { assert.equal(source, artifact.executable); copied = true; outputs.add(destination); },
      });
      assert.ok(copied);
      assert.equal(output.includes("-arm64"), target.startsWith("aarch64"));
      assert.equal(output.startsWith("SwiftTunnelLite-"), flavor === "lite");
    }
  }
  assert.equal(outputs.size, 4);
});

test("failed builds cannot publish a previous product's executable", () => {
  let copied = false;
  assert.throws(() => buildRecoverySetup({ flavor: "lite", target: "aarch64-pc-windows-msvc", version: "3.1.6", msi: "lite.msi" }, {
    stat: () => ({ isFile: () => true, size: 2_000_000 }),
    build: () => ({ ...result, status: 101 }),
    copy: () => { copied = true; },
  }), /build failed/);
  assert.equal(copied, false);
  assert.throws(() => emittedSetup({ status: 0, stdout: "" }), /one recovery executable/);
  assert.throws(() => emittedSetup({ status: 0, stdout: `${result.stdout}\n${result.stdout}` }), /one recovery executable/);
});

test("incomplete payloads and output binaries are rejected", () => {
  const options = { flavor: "lite", target: "x86_64-pc-windows-msvc", version: "3.1.6", msi: "lite.msi" };
  assert.throws(() => buildRecoverySetup(options, {
    stat: () => ({ isFile: () => true, size: 0 }),
    build: () => assert.fail("must not build an empty package"), copy: () => assert.fail("must not copy"),
  }), /payload is incomplete/);
  assert.throws(() => buildRecoverySetup(options, {
    stat: (file) => ({ isFile: () => true, size: file === artifact.executable ? 100 : 2_000_000 }),
    build: () => result, copy: () => assert.fail("must not copy"),
  }), /lacks its payload/);
  assert.throws(() => setupPlan({ ...options, version: "../bad" }), /version/);
});

test("release workflow packages recovery for both products on both architectures", () => {
  const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  for (const flavor of ["desktop", "lite"]) {
    for (const target of ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]) {
      assert.match(workflow, new RegExp(`build-recovery-setup\\.mjs --target ${target} --flavor ${flavor} `));
    }
  }
});
