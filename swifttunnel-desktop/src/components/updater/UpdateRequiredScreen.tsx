import { useUpdaterStore } from "../../stores/updaterStore";
import { systemOpenUrl } from "../../lib/commands";
import { Button } from "../ui";
import { SwiftLogo } from "../common/SwiftLogo";

const DOWNLOAD_URL = "https://swifttunnel.net";

/**
 * Blocking gate shown when the server has locked this build out (old-build
 * lockout, see the `X-SwiftTunnel-Version` gate on the web). Mirrors the
 * BannedScreen pattern: it replaces the whole app until the user updates.
 *
 * "Update now" drives the existing Tauri updater (download + install +
 * relaunch); a manual download link is the fallback for the rare case the
 * updater can't reach a newer artifact.
 */
export function UpdateRequiredScreen({ message }: { message: string }) {
  const status = useUpdaterStore((s) => s.status);
  const progress = useUpdaterStore((s) => s.progressPercent);
  const error = useUpdaterStore((s) => s.error);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);

  const busy = status === "checking" || status === "installing";

  const statusLine =
    status === "checking"
      ? "Checking for the latest version…"
      : status === "installing"
        ? progress > 0
          ? `Installing update… ${progress}%`
          : "Downloading the latest version…"
        : status === "error"
          ? (error ?? "Automatic update failed, please download manually.")
          : status === "up_to_date"
            ? "Couldn't update automatically. Download the latest version from the website."
            : null;

  return (
    <div className="flex h-screen w-screen select-none flex-col items-center justify-center gap-6 bg-bg-base px-8 text-center">
      <SwiftLogo size={60} />

      <div className="flex max-w-[420px] flex-col items-center gap-2.5">
        <span
          className="rounded-full px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em]"
          style={{
            color: "var(--color-accent-primary)",
            backgroundColor:
              "var(--color-accent-primary-soft-12, rgba(255,255,255,0.06))",
          }}
        >
          Update required
        </span>
        <h1 className="text-[19px] font-semibold tracking-tight text-text-primary">
          Time to update SwiftTunnel
        </h1>
        <p className="text-[13px] leading-relaxed text-text-muted">{message}</p>
      </div>

      {status === "installing" && (
        <div className="h-1.5 w-56 overflow-hidden rounded-full bg-bg-elevated">
          <div
            className="h-full rounded-full bg-accent-primary transition-[width] duration-300"
            style={{ width: `${Math.max(4, progress)}%` }}
          />
        </div>
      )}

      {statusLine && (
        <p
          className="text-[12px]"
          style={{
            color:
              status === "error"
                ? "var(--color-status-error)"
                : "var(--color-text-muted)",
          }}
        >
          {statusLine}
        </p>
      )}

      <div className="flex flex-col items-center gap-2.5">
        <Button
          variant="primary"
          size="lg"
          loading={busy}
          onClick={() => void checkForUpdates(true, true)}
        >
          {busy ? "Updating…" : "Update now"}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void systemOpenUrl(DOWNLOAD_URL)}
        >
          Download from swifttunnel.net
        </Button>
      </div>
    </div>
  );
}
