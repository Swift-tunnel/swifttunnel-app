import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { stageReleaseArtifacts } from "./prepare-release-attestation.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "swift-provenance-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repoRoot = path.join(root, "repo"), runnerTemp = path.join(root, "runner");
  const originals = new Map();
  const write = (file) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const bytes = Buffer.from(`test bytes for ${file}`);
    fs.writeFileSync(file, bytes);
    originals.set(file, bytes);
  };
  for (const [target, arch, suffix] of [
    ["x86_64-pc-windows-msvc", "x64", ""], ["aarch64-pc-windows-msvc", "arm64", "-arm64"],
  ]) {
    const msi = path.join(repoRoot, "target", target, "release/bundle/msi", `SwiftTunnel_3.9.4_${arch}_en-US.msi`);
    write(msi); write(`${msi}.sig`);
    write(path.join(repoRoot, "swifttunnel-lite/target-msi", arch, `SwiftTunnelLite_3.9.4_${arch}_en-US.msi`));
    for (const prefix of ["SwiftTunnel-Setup", "SwiftTunnelLite-Setup", "SwiftTunnel-Offline-Setup"]) {
      write(path.join(repoRoot, `${prefix}-3.9.4${suffix}.exe`));
    }
  }
  for (const name of ["latest.json", "swifttunnel-update-manifest.json", "swifttunnel-update-manifest.sig"]) {
    write(path.join(runnerTemp, "swifttunnel_manifest", name));
  }
  return { repoRoot, runnerTemp, version: "3.9.4", originals };
}

test("attests all 15 final files, preserves bytes and excludes unrelated files", (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.repoRoot, "unrelated.exe"), "not a release asset");
  const output = stageReleaseArtifacts(f);
  assert.equal(fs.readdirSync(output).length, 15);
  for (const [file, bytes] of f.originals) assert.deepEqual(fs.readFileSync(path.join(output, path.basename(file))), bytes);
  assert.notEqual(stageReleaseArtifacts(f), output, "reruns use a fresh staging directory");
});

test("missing offline, ARM64 or signing outputs fail closed", (t) => {
  const f = fixture(t);
  for (const [file, bytes] of f.originals) {
    fs.unlinkSync(file);
    assert.throws(() => stageReleaseArtifacts(f), undefined, file);
    fs.writeFileSync(file, bytes);
  }
});

test("empty and ambiguous outputs are refused", (t) => {
  const f = fixture(t);
  const msi = [...f.originals.keys()].find((file) => file.endsWith(".msi"));
  fs.writeFileSync(`${msi}.sig`, "");
  assert.throws(() => stageReleaseArtifacts(f), /empty release file/);
  fs.writeFileSync(`${msi}.sig`, f.originals.get(`${msi}.sig`));
  fs.writeFileSync(path.join(path.dirname(msi), "stale.msi"), "old build");
  assert.throws(() => stageReleaseArtifacts(f), /Expected one MSI/);
});
