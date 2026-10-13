import { useState } from "react";
import { Button, Dialog, ErrorBanner, Field, Icon, Row, Select, Toggle } from "../ui";
import { gamesCleanup, gamesScanImports, gamesFlags } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import type { FlagCleanupReport, RobloxCleanupKind, RobloxCleanupReport, RobloxImportPreview, RobloxSettingsConfig } from "../../lib/types";
import { Notice } from "./Notice";

/** The rows of the Games tab's maintenance section. The section itself, and its heading, belong to the tab. */
export function GameToolsPanel({ onImport, disabled }: { onImport: (patch: Partial<RobloxSettingsConfig>) => void; disabled: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState<RobloxImportPreview | null>(null);
  const [source, setSource] = useState(-1);
  const [fps, setFps] = useState(true);
  const [graphics, setGraphics] = useState(true);
  const [cleanup, setCleanup] = useState<{ kind: RobloxCleanupKind; report: RobloxCleanupReport } | null>(null);
  const [flagsPreview, setFlagsPreview] = useState<FlagCleanupReport | null>(null);
  async function run(action: () => Promise<void>) {
    setBusy(true); setError(null); setNotice(null);
    try { await action(); } catch (error) { setError(formatErrorMessage(error)); }
    finally { setBusy(false); }
  }
  const flags = preview?.sources[source];
  const patch: Partial<RobloxSettingsConfig> = {};
  if (fps && preview?.fps_cap != null) Object.assign(patch, { unlock_fps: true, target_fps: preview.fps_cap });
  if (graphics && preview?.graphics_quality) patch.graphics_quality = preview.graphics_quality;
  const hasPatch = Object.keys(patch).length > 0;
  const size = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return <>
    {(error || notice) && <div className="flex flex-col gap-2 border-b border-border-subtle p-3">
      {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      {notice && <Notice inset>{notice}</Notice>}
    </div>}
    <div className="divide-y divide-border-subtle">
      <Row label="Bring your settings" desc="Bring over your FPS and graphics settings from another launcher.">
        <Button size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => { const result = await gamesScanImports(); setPreview(result); setSource(-1); setFps(true); setGraphics(true); })}>Import launcher settings</Button>
      </Row>
      <Row label="Reclaim storage" desc="Clear Roblox logs and cached files older than seven days.">
        <div className="flex flex-wrap justify-end gap-2">{(["logs", "assets"] as const).map(kind => <Button key={kind} size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => { setCleanup({ kind, report: await gamesCleanup(kind) }); })}>{kind === "logs" ? "Clean old logs" : "Clean old assets"}</Button>)}</div>
      </Row>
      <Row label="Keep useful flags" desc="Remove flags Roblox no longer allows. A backup is kept so you can undo.">
        <div className="flex flex-wrap justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => setFlagsPreview(await gamesFlags("preview")))}>Review unsupported flags</Button>
        <Button size="sm" variant="ghost" disabled={busy || disabled} onClick={() => void run(async () => { const report = await gamesFlags("undo"); setNotice(`Restored ${report.files_changed} flag files.${report.skipped.length ? ` ${report.skipped.length} items were preserved because their files changed or moved.` : ""}`); })}>Undo last flag cleanup</Button></div>
      </Row>
    </div>
    <Dialog open={!!preview} title="Import Roblox settings" onClose={() => { if (!busy) setPreview(null); }}
      description="Pick what to bring over, then press Apply on Roblox settings.">
      <div className="flex flex-col gap-4">
        <div className="-mr-2 flex max-h-[52vh] flex-col gap-4 overflow-y-auto pr-2">
          <Field label="Inspect existing flags" hint={preview && !preview.sources.length ? "No existing launcher flag files were found." : undefined}><Select block aria-label="Launcher flag source" value={source} disabled={busy}
            onChange={e => setSource(Number(e.target.value))}>
            <option value={-1}>Keep my current flags</option>
            {preview?.sources.map((entry, i) => <option key={i} value={i}>{entry.source} ({entry.accepted} supported{entry.error ? ", could not read" : ""})</option>)}
          </Select></Field>
          {flags?.error && <p className="text-[11.5px] leading-snug text-status-error">{flags.error}</p>}
          {flags?.skipped.length ? <div className="rounded-[10px] bg-bg-base px-3.5 py-3 text-[11.5px] text-text-secondary">
            <p>{flags.skipped.length} flags will be skipped:</p><ul className="mt-2 list-inside list-disc break-all font-mono text-[10.5px] leading-relaxed text-text-muted">{flags.skipped.slice(0, 20).map(flag => <li key={flag}>{flag}</li>)}</ul>
            {flags.skipped.length > 20 && <p className="mt-2">And {flags.skipped.length - 20} more.</p>}
          </div> : null}
          {flags?.accepted ? <details className="group"><summary className="flex cursor-pointer list-none items-center gap-2 text-[11.5px] text-text-secondary transition-colors hover:text-text-primary [&::-webkit-details-marker]:hidden"><Icon name="chevron-right" size={12} strokeWidth={2.2} className="transition-transform group-open:rotate-90" />Review {flags.accepted} supported flags</summary><pre className="mt-2 overflow-x-auto rounded-[10px] bg-bg-base p-3 font-mono text-[11px] leading-relaxed text-text-secondary">{flags.json}</pre></details> : null}
          <div className="flex flex-col gap-1.5">
            <p className="text-[11px] font-medium text-text-secondary">Found in your Roblox settings:</p>
            {(preview?.fps_cap != null || preview?.graphics_quality) && <div className="divide-y divide-border-subtle rounded-[10px] bg-bg-base">
              {preview?.fps_cap != null && <div className="flex items-center justify-between gap-4 px-3.5 py-2.5 text-[12px] text-text-primary">Frame-rate cap: {preview.fps_cap} FPS<Toggle size="sm" enabled={fps} onChange={setFps} ariaLabel={`Import frame-rate cap: ${preview.fps_cap} FPS`} /></div>}
              {preview?.graphics_quality && <div className="flex items-center justify-between gap-4 px-3.5 py-2.5 text-[12px] text-text-primary">Graphics: {preview.graphics_quality}<Toggle size="sm" enabled={graphics} onChange={setGraphics} ariaLabel={`Import graphics: ${preview.graphics_quality}`} /></div>}
            </div>}
          </div>
          <p className="text-[11px] leading-snug text-text-muted">Flags are shown for reference. Edit them in FastFlags.</p>
        </div>
        <div className="flex justify-end gap-2"><Button size="sm" variant="secondary" onClick={() => setPreview(null)}>Cancel</Button>
          <Button size="sm" disabled={!hasPatch || disabled} onClick={() => { onImport(patch); setPreview(null); setNotice("Imported. Press Apply to use them."); }}>Use these settings</Button></div>
      </div>
    </Dialog>
    <Dialog open={!!flagsPreview} title="Clean unsupported flag overrides?" onClose={() => { if (!busy) setFlagsPreview(null); }} description="A backup is kept so you can undo.">
      <div className="flex flex-col gap-4"><div className="flex flex-col gap-2 text-[12px] leading-relaxed text-text-secondary"><p className="rounded-[10px] bg-bg-base px-3.5 py-3 font-medium text-text-primary">{flagsPreview?.flags_removed ?? 0} unsupported or invalid flags in {flagsPreview?.files_changed ?? 0} files.</p><p className="text-[11.5px] text-text-muted">Close Roblox Player and Studio first.</p>{flagsPreview?.skipped.map((message,i) => <p key={i} className="text-[11.5px] text-text-muted">{message}</p>)}</div>{error && <ErrorBanner tone="error">{error}</ErrorBanner>}
      <div className="flex justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy} onClick={() => setFlagsPreview(null)}>Cancel</Button><Button size="sm" variant="destructive" loading={busy} disabled={!flagsPreview?.flags_removed} onClick={() => void run(async () => { const report = await gamesFlags("clean"); setFlagsPreview(null); setNotice(`Removed ${report.flags_removed} overrides from ${report.files_changed} files. Use Undo last flag cleanup to restore them.${report.skipped.length ? ` ${report.skipped.length} items were left unchanged.` : ""}`); })}>Clean & keep backup</Button></div></div>
    </Dialog>
    <Dialog open={!!cleanup} title={cleanup?.kind === "logs" ? "Clean old player logs?" : "Clean old cached assets?"}
      onClose={() => { if (!busy) setCleanup(null); }} description="Close Roblox first. Cached files download again when they are needed.">
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2 text-[11.5px] leading-relaxed text-text-muted">
          <p className="rounded-[10px] bg-bg-base px-3.5 py-3 text-[12px] font-medium text-text-primary">{cleanup?.report.files ?? 0} eligible files · {size(cleanup?.report.bytes ?? 0)}</p>
          {!!cleanup?.report.skipped && <p>{cleanup.report.skipped} items could not be inspected.</p>}
          {cleanup?.report.partial && <p>This scan reached its limit. More files may remain.</p>}
          {error && <p role="alert" className="text-status-error">{error}</p>}
        </div>
        <div className="flex justify-end gap-2"><Button size="sm" variant="secondary" disabled={busy} onClick={() => setCleanup(null)}>Cancel</Button>
          <Button size="sm" variant="destructive" loading={busy} disabled={!cleanup?.report.files} onClick={() => { if (cleanup) void run(async () => {
            const result = await gamesCleanup(cleanup.kind, true); setCleanup(null);
            setNotice(`Removed ${result.files} files (${size(result.bytes)}).${result.skipped ? ` ${result.skipped} items were skipped.` : ""}${result.partial ? " Cleanup reached its limit; scan again to check for more." : ""}`);
          }); }}>Clean eligible files</Button></div>
      </div>
    </Dialog>
  </>;
}
