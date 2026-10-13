import { useEffect, useState } from "react";
import { Button, ErrorBanner, Panel } from "../ui";
import {
  gamesSessionReports,
  gamesClearSessionReports,
  gamesLaunchDiagnostics,
} from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import type { GameSessionReport } from "../../lib/types";
import { Notice } from "./Notice";
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
  const value = (n: number | null | undefined, unit: string) =>
    n == null ? "Unavailable" : `${n} ${unit}`;
  return (
    <Panel
      eyebrow="Recent session reports"
      desc="The last 20 sessions stay on this PC. Network readings are path estimates; frame gaps come from Windows Present events. Relay loss measures control probes, not game packets. These are not Roblox's NetworkPing or GPU frame times."
    >
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <Notice>{notice}</Notice>}
      <div className="mb-3 flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
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
          Clear reports
        </Button>
      </div>
      {diagnostics.length > 0 && (
        <div className="mb-3 rounded-[10px] bg-bg-base px-3.5 py-3">
          {diagnostics.map((note) => (
            <p className="mb-1 text-[11.5px] text-text-muted" key={note}>
              {note}
            </p>
          ))}
        </div>
      )}
      {!reports.length && (
        <p className="text-[12px] text-text-muted">
          Reports appear after a detected game ends.
        </p>
      )}
      <div className="max-h-[350px] space-y-2 overflow-y-auto">
        {reports.map((r, i) => (
          <div
            key={`${r.started_at}:${i}`}
            className="rounded-[10px] bg-bg-base px-3.5 py-3"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[12.5px] font-medium text-text-primary">
                  {r.game_name}
                </p>
                <p className="mt-1 text-[11px] text-text-muted">
                  {new Date(r.started_at * 1000).toLocaleString()} ·{" "}
                  {Math.round(r.duration_seconds / 60)} min
                  {r.location ? ` · ${r.location}` : ""}
                  {r.ended_without_leave
                    ? " · Ended without a leave event"
                    : ""}
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
                    setNotice("Session report copied for support.");
                  })
                }
              >
                Copy
              </Button>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-text-muted">
              <span>Average FPS · {value(r.average_fps, "FPS")}</span>
              <span>Lowest sampled FPS · {value(r.low_fps, "FPS")}</span>
              <span>Estimated path · {value(r.average_network_ms, "ms")}</span>
              <span>
                Path variation · {value(r.network_variation_ms, "ms")}
              </span>
              <span>
                Present gaps &gt;50 ms ·{" "}
                {r.peak_frame_ms == null ? "Unavailable" : r.frame_spikes}
              </span>
              <span>Longest present gap · {value(r.peak_frame_ms, "ms")}</span>
              <span>
                Latest relay probe loss · {value(r.relay_probe_loss_pct, "%")}
              </span>
              <span>
                Relay probe variation ·{" "}
                {value(r.relay_probe_variation_ms, "ms")}
              </span>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
