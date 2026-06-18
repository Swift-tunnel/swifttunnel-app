import { useMemo } from "react";
import { useUpdaterStore } from "../../stores/updaterStore";
import { Button, Dialog } from "../ui";

function cleanMarkdown(text: string) {
  return text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*/g, "")
    .trim();
}

function extractReleaseNotes(notes: string | null) {
  if (!notes) return [];

  return notes
    .split(/\r?\n/)
    .map((line) => cleanMarkdown(line.replace(/^[-*•·]\s*/, "")))
    .filter((line) => line.length > 0)
    .filter((line) => !/^#+\s*what'?s changed$/i.test(line))
    .filter((line) => !/^what'?s changed$/i.test(line))
    .filter((line) => !/^release:?/i.test(line))
    .filter((line) => !line.includes("github.com/Swift-tunnel/swifttunnel-app/releases"))
    .slice(0, 8);
}

export function WhatsNewDialog() {
  const status = useUpdaterStore((s) => s.status);
  const availableVersion = useUpdaterStore((s) => s.availableVersion);
  const releaseNotes = useUpdaterStore((s) => s.releaseNotes);
  const showWhatsNew = useUpdaterStore((s) => s.showWhatsNew);
  const dismissWhatsNew = useUpdaterStore((s) => s.dismissWhatsNew);
  const installUpdate = useUpdaterStore((s) => s.installUpdate);

  const notes = useMemo(
    () => extractReleaseNotes(releaseNotes),
    [releaseNotes],
  );
  const open = showWhatsNew && status === "update_available" && !!availableVersion;

  return (
    <Dialog
      open={open}
      onClose={dismissWhatsNew}
      title={`SwiftTunnel v${availableVersion} is available`}
      description="What's new in this update"
      maxWidth={560}
    >
      <div className="space-y-4">
        <div
          className="rounded-[var(--radius-card)] p-4"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          {notes.length > 0 ? (
            <ul className="space-y-2 text-[12px] leading-relaxed text-text-secondary">
              {notes.map((note) => (
                <li key={note} className="flex gap-2">
                  <span className="mt-[0.55em] h-1.5 w-1.5 shrink-0 rounded-full bg-accent-primary" />
                  <span>{note}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] leading-relaxed text-text-secondary">
              This update is ready to install.
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={dismissWhatsNew}>
            Later
          </Button>
          <Button
            variant="primary"
            size="md"
            onClick={() => {
              void installUpdate();
            }}
          >
            Update now
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
