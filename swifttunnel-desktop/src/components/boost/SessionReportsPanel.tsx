import { useEffect, useState } from "react";
import { Button, ErrorBanner, Icon } from "../ui";
import {
  gamesSessionReports,
  gamesClearSessionReports,
  gamesLaunchDiagnostics,
} from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import type { GameSessionReport } from "../../lib/types";
import { Notice } from "./Notice";

/** One reading. A missing one shows a dash, never a made-up zero. */
function Stat({ label, value, unit }: { label: string; value: number | null | undefined; unit?: string }) {
  return (
    <div className="px-3.5 py-2.5">
      <p className="font-mono text-[13px] font-semibold leading-none text-text-primary">
        {value == null ? <span className="text-text-dimmed">-</span> : value}
        {value != null && unit && (
          <span className="ml-1 text-[10px] font-medium text-text-dimmed">{unit}</span>
        )}
      </p>
      <p className="mt-1.5 text-[10.5px] leading-tight text-text-muted">{label}</p>
    </div>
  );
}

/** The body of the library's "Session reports" section; the section and its heading belong to the library. */
export function SessionReportsPanel() {
  const [reports, setReports] = useState<GameSessionReport[]>([]);
  const [diagnostics, setDiagnostics] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    void gamesSessionReports()
      .then((rows) => {
        if (alive) setReports(rows);
      })
      .catch((e) => {
        if (alive) setError(formatErrorMessage(e));
      });
    return () => {
      alive = false;
    };
  }, []);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(formatErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex flex-col gap-3">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <Notice inset>{notice}</Notice>}
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-auto text-[11.5px] text-text-muted">
          Your last 20 sessions, kept on this PC.
        </p>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          leadingIcon={<Icon name="refresh" size={13} />}
          onClick={() =>
            void run(async () => {
              setReports(await gamesSessionReports());
            })
          }
        >
          Refresh
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              setDiagnostics(await gamesLaunchDiagnostics());
            })
          }
        >
          Launch diagnostics
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={busy || !reports.length}
          onClick={() =>
            void run(async () => {
              await gamesClearSessionReports();
              setReports([]);
            })
          }
        >
          Clear
        </Button>
      </div>
      {diagnostics.length > 0 && (
        <ul className="flex flex-col gap-1.5 rounded-[10px] bg-bg-base px-3.5 py-3">
          {diagnostics.map((note) => (
            <li
              className="flex gap-2 text-[11.5px] leading-snug text-text-secondary"
              key={note}
            >
              <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-text-dimmed" />
              {note}
            </li>
          ))}
        </ul>
      )}
      {!reports.length && (
        <p className="py-5 text-center text-[12px] text-text-muted">
          Reports show up here after a game ends.
        </p>
      )}
      {reports.length > 0 && (
        <div className="flex max-h-[380px] flex-col gap-2 overflow-y-auto">
          {reports.map((r, i) => (
            <article
              key={`${r.started_at}:${i}`}
              className="rounded-[10px] bg-bg-base"
            >
              <div className="flex items-center justify-between gap-3 py-2.5 pl-3.5 pr-2">
                <div className="min-w-0">
                  <p className="truncate text-[12.5px] font-medium leading-tight text-text-primary">
                    {r.game_name}
                  </p>
                  <p className="mt-1 text-[11px] text-text-muted">
                    {new Date(r.started_at * 1000).toLocaleString()} ·{" "}
                    {Math.round(r.duration_seconds / 60)} min
                    {r.location ? ` · ${r.location}` : ""}
                    {r.ended_without_leave ? " · Closed unexpectedly" : ""}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    void run(async () => {
                      await navigator.clipboard.writeText(
                        JSON.stringify(r, null, 2),
                      );
                      setNotice("Report copied.");
                    })
                  }
                >
                  Copy
                </Button>
              </div>
              <div className="grid grid-cols-4 border-t border-border-subtle max-[820px]:grid-cols-2">
                <Stat label="Average FPS" value={r.average_fps} />
                <Stat label="Lowest FPS" value={r.low_fps} />
                <Stat label="Ping estimate" value={r.average_network_ms} unit="ms" />
                <Stat label="Ping variation" value={r.network_variation_ms} unit="ms" />
                <Stat
                  label="Stutters over 50 ms"
                  value={r.peak_frame_ms == null ? null : r.frame_spikes}
                />
                <Stat label="Longest stutter" value={r.peak_frame_ms} unit="ms" />
                <Stat label="Relay loss" value={r.relay_probe_loss_pct} unit="%" />
                <Stat label="Relay jitter" value={r.relay_probe_variation_ms} unit="ms" />
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
