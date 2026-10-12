import { useState } from "react";
import { Button, Dialog, ErrorBanner, Panel } from "../ui";
import { gamesCleanup, gamesScanImports, gamesFlags } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import type { FlagCleanupReport, RobloxCleanupKind, RobloxCleanupReport, RobloxImportPreview, RobloxSettingsConfig } from "../../lib/types";

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
  return <Panel eyebrow="Maintenance" title="Existing settings & storage" desc="Review imports before applying. Cleanup only includes eligible files older than seven days." watermark={{icon:"repair",at:"top-right",size:130,rotate:-12,opacity:.04}}>
    {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
    {notice && <p role="status" className="mb-3 text-xs text-text-secondary">{notice}</p>}
    <div className="grid gap-3 min-[1100px]:grid-cols-3">
      <section className="rounded-xl border border-border-subtle bg-bg-base p-4">
        <h3 className="text-sm font-semibold text-text-primary">Bring your settings</h3>
        <p className="mb-4 mt-2 text-xs leading-relaxed text-text-muted">Import FPS and graphics preferences. Review flag files here and edit your overrides in FastFlags.</p>
        <Button size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => { const result = await gamesScanImports(); setPreview(result); setSource(-1); setFps(true); setGraphics(true); })}>Import launcher settings</Button>
      </section>
      <section className="rounded-xl border border-border-subtle bg-bg-base p-4">
        <h3 className="text-sm font-semibold text-text-primary">Reclaim storage</h3>
        <p className="mb-4 mt-2 text-xs leading-relaxed text-text-muted">Preview old player logs and cached assets. Only eligible files older than seven days are included.</p>
        <div className="flex flex-wrap gap-2">{(["logs", "assets"] as const).map(kind => <Button key={kind} size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => { setCleanup({ kind, report: await gamesCleanup(kind) }); })}>{kind === "logs" ? "Clean old logs" : "Clean old assets"}</Button>)}</div>
      </section>
      <section className="rounded-xl border border-border-subtle bg-bg-base p-4">
        <h3 className="text-sm font-semibold text-text-primary">Keep useful flags</h3>
        <p className="mb-4 mt-2 text-xs leading-relaxed text-text-muted">Remove unsupported or invalid overrides with an exact backup. Undo preserves edits made after cleanup.</p>
        <div className="flex flex-wrap gap-2"><Button size="sm" variant="secondary" disabled={busy || disabled} onClick={() => void run(async () => setFlagsPreview(await gamesFlags("preview")))}>Review unsupported flags</Button>
        <Button size="sm" variant="ghost" disabled={busy || disabled} onClick={() => void run(async () => { const report = await gamesFlags("undo"); setNotice(`Restored ${report.files_changed} flag files.${report.skipped.length ? ` ${report.skipped.length} items were preserved because their files changed or moved.` : ""}`); })}>Undo last flag cleanup</Button></div>
      </section>
    </div>
    <Dialog open={!!preview} title="Import Roblox settings" onClose={() => { if (!busy) setPreview(null); }}
      description="Copies supported values into your pending settings. Review them below, then use Apply. Your other launcher stays installed.">
      <div className="max-h-[60vh] overflow-y-auto p-4 text-xs text-text-secondary">
        <label className="block">Inspect existing flags<select aria-label="Launcher flag source" value={source} disabled={busy}
          onChange={e => setSource(Number(e.target.value))} className="mt-2 block w-full rounded-lg border border-border-subtle bg-bg-base p-2 text-text-primary">
          <option value={-1}>Keep my current flags</option>
          {preview?.sources.map((entry, i) => <option key={i} value={i}>{entry.source} ({entry.accepted} supported{entry.error ? ", could not read" : ""})</option>)}
        </select></label>
        {preview && !preview.sources.length && <p className="mt-2 text-text-muted">No existing launcher flag files were found.</p>}
        {flags?.error && <p className="mt-2 text-status-error">{flags.error}</p>}
        {flags?.skipped.length ? <div className="mt-3 rounded-lg bg-bg-hover p-3">
          <p>{flags.skipped.length} flags will be skipped:</p><ul className="mt-2 list-inside list-disc text-[11px]">{flags.skipped.slice(0, 20).map(flag => <li key={flag}>{flag}</li>)}</ul>
          {flags.skipped.length > 20 && <p className="mt-2">And {flags.skipped.length - 20} more.</p>}
        </div> : null}
        {flags?.accepted ? <details className="mt-3"><summary className="cursor-pointer">Review {flags.accepted} supported flags</summary><pre className="mt-2 overflow-x-auto rounded-lg bg-bg-base p-2 text-[11px]">{flags.json}</pre></details> : null}
        <p className="mt-4 text-text-muted">These shared Roblox preferences come from the current Roblox settings file:</p>
        {preview?.fps_cap != null && <label className="mt-3 flex gap-2"><input type="checkbox" checked={fps} onChange={e => setFps(e.target.checked)} />Frame-rate cap: {preview.fps_cap} FPS</label>}
        {preview?.graphics_quality && <label className="mt-3 flex gap-2"><input type="checkbox" checked={graphics} onChange={e => setGraphics(e.target.checked)} />Graphics: {preview.graphics_quality}</label>}
        <p className="mt-4 text-[11px] text-text-muted">Only FPS and graphics are imported here. Flag files are shown for inspection; use FastFlags to edit them. Themes, mods, accounts and integrations are not imported.</p>
      </div>
      <div className="flex justify-end gap-2 border-t border-border-subtle p-4"><Button size="sm" variant="ghost" onClick={() => setPreview(null)}>Cancel</Button>
        <Button size="sm" disabled={!hasPatch || disabled} onClick={() => { onImport(patch); setPreview(null); setNotice("Imported into pending settings. Review the values, then use Apply."); }}>Use these settings</Button></div>
    </Dialog>
    <Dialog open={!!flagsPreview} title="Clean unsupported flag overrides?" onClose={() => { if (!busy) setFlagsPreview(null); }} description="Review the count before cleaning. An exact backup is kept for undo, and newer edits are preserved.">
      <div className="space-y-3 p-5 text-xs text-text-secondary"><p>{flagsPreview?.flags_removed ?? 0} unsupported or invalid flags in {flagsPreview?.files_changed ?? 0} files.</p><p className="text-text-muted">Close Roblox Player and Studio first. This changes existing flag files; it does not uninstall a launcher.</p>{flagsPreview?.skipped.map((message,i) => <p key={i} className="text-text-muted">{message}</p>)}{error && <ErrorBanner tone="error">{error}</ErrorBanner>}</div>
      <div className="flex justify-end gap-2 border-t border-border-subtle p-4"><Button variant="ghost" disabled={busy} onClick={() => setFlagsPreview(null)}>Cancel</Button><Button variant="destructive" loading={busy} disabled={!flagsPreview?.flags_removed} onClick={() => void run(async () => { const report = await gamesFlags("clean"); setFlagsPreview(null); setNotice(`Removed ${report.flags_removed} overrides from ${report.files_changed} files. Use Undo last flag cleanup to restore them.${report.skipped.length ? ` ${report.skipped.length} items were left unchanged.` : ""}`); })}>Clean & keep backup</Button></div>
    </Dialog>
    <Dialog open={!!cleanup} title={cleanup?.kind === "logs" ? "Clean old player logs?" : "Clean old cached assets?"}
      onClose={() => { if (!busy) setCleanup(null); }} description="Close Roblox first. Cleanup preserves settings, databases and login files. Cached assets may need to download again.">
      <div className="p-4 text-xs text-text-secondary">
        <p>{cleanup?.report.files ?? 0} eligible files · {size(cleanup?.report.bytes ?? 0)}</p>
        {!!cleanup?.report.skipped && <p className="mt-2">{cleanup.report.skipped} items could not be inspected.</p>}
        {cleanup?.report.partial && <p className="mt-2">This scan reached its limit. More files may remain.</p>}
        {error && <p role="alert" className="mt-2 text-status-error">{error}</p>}
      </div>
      <div className="flex justify-end gap-2 border-t border-border-subtle p-4"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setCleanup(null)}>Cancel</Button>
        <Button size="sm" variant="destructive" loading={busy} disabled={!cleanup?.report.files} onClick={() => { if (cleanup) void run(async () => {
          const result = await gamesCleanup(cleanup.kind, true); setCleanup(null);
          setNotice(`Removed ${result.files} files (${size(result.bytes)}).${result.skipped ? ` ${result.skipped} items were skipped.` : ""}${result.partial ? " Cleanup reached its limit; scan again to check for more." : ""}`);
        }); }}>Clean eligible files</Button></div>
    </Dialog>
  </Panel>;
}
