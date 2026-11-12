import { randomBytes, createHmac } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
export function accountToken(key, account) {
  if (
    !Buffer.isBuffer(key) ||
    key.length !== 32 ||
    typeof account !== "string" ||
    !account.trim()
  )
    throw Error("Invalid account identity input");
  return createHmac("sha256", key)
    .update("account\0" + account.trim())
    .digest("hex");
}
export function init(dir) {
  if (/[/\\]OneDrive([/\\]|$)/i.test(path.resolve(dir)))
    throw Error("Use a folder outside OneDrive");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "campaign-key.local"), randomBytes(32), {
    flag: "wx",
    mode: 0o600,
  });
  fs.writeFileSync(
    path.join(dir, "campaign.json"),
    JSON.stringify({ schema: 1, campaign: randomBytes(16).toString("hex") }),
    { flag: "wx" },
  );
}
export function participant(dir, accountFile, outFile) {
  const key = fs.readFileSync(path.join(dir, "campaign-key.local"));
  const { campaign } = JSON.parse(
    fs.readFileSync(path.join(dir, "campaign.json"), "utf8"),
  );
  const account = accountToken(key, fs.readFileSync(accountFile, "utf8"));
  fs.writeFileSync(
    outFile,
    JSON.stringify(
      { schema: 1, campaign, account, device: randomBytes(32).toString("hex") },
      null,
      2,
    ),
    { flag: "wx", mode: 0o600 },
  );
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.resolve(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, "$1"))
) {
  const [command, dir, input, out] = process.argv.slice(2);
  if (command === "init" && dir) init(dir);
  else if (command === "participant" && dir && input && out)
    participant(dir, input, out);
  else
    throw Error(
      "Usage: campaign.mjs init DIR | participant DIR PRIVATE_ACCOUNT_ID_FILE PARTICIPANT_JSON",
    );
}
