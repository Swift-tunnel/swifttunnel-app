import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { validateRecord } from "./model.mjs";

const [dir, inventoryFile, outFile, ...flags] = process.argv.slice(2);
if (!dir || !inventoryFile || !outFile || !flags.includes("--run"))
  throw Error(
    "Usage: collect-relays.mjs CAMPAIGN_DIR INVENTORY_JSON NEW_OUTPUT_JSONL --run [--seconds N]",
  );
const durationIndex = flags.indexOf("--seconds");
const seconds = durationIndex === -1 ? 600 : Number(flags[durationIndex + 1]);
if (!Number.isSafeInteger(seconds) || seconds < 5 || seconds > 86400)
  throw Error("Duration must be 5-86400 seconds");
const campaign = JSON.parse(
  fs.readFileSync(path.join(dir, "campaign.json"), "utf8"),
);
const key = fs.readFileSync(path.join(dir, "campaign-key.local"));
if (key.length !== 32 || !/^[0-9a-f]{32}$/.test(campaign.campaign))
  throw Error("Invalid campaign");
const inventory = JSON.parse(fs.readFileSync(inventoryFile, "utf8"));
if (!Array.isArray(inventory) || !inventory.length || inventory.length > 64)
  throw Error("Inventory must have 1-64 relays");
const ids = new Set();
for (const relay of inventory) {
  if (
    !/^[a-z0-9-]{1,64}$/.test(relay.id) ||
    ids.has(relay.id) ||
    !/^[a-zA-Z0-9.-]{1,253}$/.test(relay.host) ||
    !/^[a-z_][a-z0-9_-]{0,31}$/.test(relay.user) ||
    typeof relay.key_file !== "string"
  )
    throw Error("Invalid relay inventory");
  ids.add(relay.id);
}
const output = fs.openSync(outFile, "wx", 0o600);
const maxBytes = 256 * 1024 * 1024;
let written = 0,
  stopping = false,
  failed = false;
const children = new Set();
const stop = () => {
  stopping = true;
  for (const child of children) child.kill();
};
const write = (record) => {
  const line = JSON.stringify(record) + "\n";
  if (written + Buffer.byteLength(line) > maxBytes) {
    failed = true;
    stop();
    return;
  }
  fs.writeSync(output, line);
  written += Buffer.byteLength(line);
};
write({
  schema: 1,
  kind: "campaign_relays",
  campaign: campaign.campaign,
  relays: [...ids].sort(),
  interval_ms: 5000,
});
const template = fs.readFileSync(
  new URL("./relay-reader.py", import.meta.url),
  "utf8",
);
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
try {
  await Promise.all(
    inventory.map(
      (relay) =>
        new Promise((resolve) => {
          const settings = JSON.stringify({
            key: key.toString("hex"),
            campaign: campaign.campaign,
            relay: relay.id,
            seconds,
            interval_ms: 5000,
          });
          // The settings JSON contains only validated identifiers, numbers and hex.
          const script = template.replace("__SETTINGS__", settings);
          const child = spawn(
            "ssh",
            [
              "-i",
              relay.key_file,
              "-o",
              "BatchMode=yes",
              "-o",
              "ConnectTimeout=8",
              "-o",
              "StrictHostKeyChecking=yes",
              `${relay.user}@${relay.host}`,
              "sudo -n python3 -",
            ],
            { windowsHide: true },
          );
          children.add(child);
          let buffer = "";
          const timer = setTimeout(() => child.kill(), (seconds + 15) * 1000);
          child.stdout.on("data", (chunk) => {
            if (stopping) return;
            buffer += chunk.toString("utf8");
            if (buffer.length > 4 * 1024 * 1024) {
              failed = true;
              child.kill();
              return;
            }
            let index;
            while ((index = buffer.indexOf("\n")) !== -1) {
              const line = buffer.slice(0, index);
              buffer = buffer.slice(index + 1);
              try {
                const row = JSON.parse(line);
                validateRecord(row);
                if (
                  row.kind !== "relay" ||
                  row.campaign !== campaign.campaign ||
                  row.relay !== relay.id
                )
                  throw Error("identity");
                write(row);
              } catch {
                failed = true;
                child.kill();
                return;
              }
            }
          });
          child.stderr.on("data", () => {}); // Never print remote configuration or SSH banners.
          child.stdin.on("error", () => {});
          child.stdin.end(script);
          child.on("error", () => {
            failed = true;
            clearTimeout(timer);
            children.delete(child);
            resolve();
          });
          child.on("close", (code) => {
            clearTimeout(timer);
            children.delete(child);
            if (code !== 0 && !stopping) failed = true;
            resolve();
          });
        }),
    ),
  );
} finally {
  stop();
  fs.closeSync(output);
}
if (failed)
  console.error(
    "Some relay observations failed. Missing samples remain unknown; inspect coverage in the offline report.",
  );
console.log(
  "Local collection finished. No relay configuration or forwarding was changed.",
);
if (failed) process.exitCode = 1;
