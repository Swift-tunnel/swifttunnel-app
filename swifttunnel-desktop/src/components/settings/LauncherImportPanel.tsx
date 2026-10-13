import { useState } from "react";
import {
  Button,
  Dialog,
  ErrorBanner,
  Field,
  Panel,
  Row,
  Select,
  Toggle,
} from "../ui";
import { gamesScanImports } from "../../lib/commands";
import { formatErrorMessage } from "../../lib/errors";
import { useSettingsStore } from "../../stores/settingsStore";
import type {
  RobloxImportPreview,
  RobloxSettingsConfig,
} from "../../lib/types";
import { Notice } from "../boost/Notice";

export function LauncherImportPanel() {
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<RobloxImportPreview | null>(null);
  const [source, setSource] = useState(-1);
  const [fps, setFps] = useState(true);
  const [graphics, setGraphics] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const flags = preview?.sources[source];
  const patch: Partial<RobloxSettingsConfig> = {};
  if (fps && preview?.fps_cap != null)
    Object.assign(patch, { unlock_fps: true, target_fps: preview.fps_cap });
  if (graphics && preview?.graphics_quality)
    patch.graphics_quality = preview.graphics_quality;
  if (flags?.accepted && !flags.error)
    Object.assign(patch, {
      custom_fflags_enabled: true,
      custom_fflags_json: flags.json,
      ultraboost: false,
    });

  async function review(next: boolean) {
    setEnabled(next);
    setError(null);
    setNotice(null);
    setPreview(null);
    setSource(-1);
    setFps(true);
    setGraphics(true);
    if (!next) return;
    setBusy(true);
    try {
      setPreview(await gamesScanImports());
    } catch (error) {
      setError(formatErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }
  async function apply() {
    setBusy(true);
    setError(null);
    const store = useSettingsStore.getState();
    const before = store.settings.config;
    const config = {
      ...before,
      profile: "Custom" as const,
      roblox_settings: { ...before.roblox_settings, ...patch },
    };
    store.update({ config });
    try {
      await store.save(true);
      setEnabled(false);
      setPreview(null);
      setNotice("Settings imported. Used the next time you play from Games.");
    } catch (error) {
      if (useSettingsStore.getState().settings.config === config)
        store.update({ config: before });
      setError(formatErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel eyebrow="Roblox" flush>
      <div className="border-t border-border-subtle">
      <Row
        anchorId="launcher_import"
        label="Import launcher settings"
        desc="Bring over supported Roblox settings from another launcher."
      >
        <Toggle
          enabled={enabled}
          disabled={busy}
          ariaLabel="Import launcher settings"
          onChange={(next) => void review(next)}
        />
      </Row>
      </div>
      {notice && (
        <div className="px-4 pb-3">
          <Notice inset>{notice}</Notice>
        </div>
      )}
      {!enabled && error && (
        <div className="px-4 pb-3">
          <ErrorBanner tone="error">{error}</ErrorBanner>
        </div>
      )}
      <Dialog
        open={enabled}
        title="Import Roblox settings"
        description="Choose what to bring over. Used the next time you play from Games."
        onClose={() => {
          if (!busy) setEnabled(false);
        }}
      >
        <div className="flex flex-col gap-4">
          {busy && !preview && (
            <Notice busy>Looking for launcher settings...</Notice>
          )}
          {error && <ErrorBanner tone="error">{error}</ErrorBanner>}
          {preview && (
            <>
              <Field
                label="Launcher flags"
                hint={
                  !preview.sources.length
                    ? "No launcher flag files found."
                    : undefined
                }
              >
                <Select
                  block
                  aria-label="Launcher flag source"
                  value={source}
                  disabled={busy}
                  onChange={(e) => setSource(Number(e.target.value))}
                >
                  <option value={-1}>Keep my current flags</option>
                  {preview.sources.map((entry, i) => (
                    <option key={i} value={i}>
                      {entry.source} ({entry.accepted} supported
                      {entry.error ? ", could not read" : ""})
                    </option>
                  ))}
                </Select>
              </Field>
              {flags?.error && (
                <ErrorBanner tone="error">{flags.error}</ErrorBanner>
              )}
              {!!flags?.skipped.length && (
                <p className="text-[11.5px] text-text-muted">
                  {flags.skipped.length} unsupported or invalid flags will be
                  skipped.
                </p>
              )}
              {!!flags?.accepted && (
                <details>
                  <summary className="cursor-pointer text-[11.5px] text-text-secondary">
                    Review {flags.accepted} supported flags
                  </summary>
                  <pre className="mt-2 max-h-48 overflow-auto rounded-[10px] bg-bg-base p-3 font-mono text-[11px] text-text-muted">
                    {flags.json}
                  </pre>
                </details>
              )}
              {preview.fps_cap != null && (
                <Row label={`Frame-rate cap: ${preview.fps_cap} FPS`}>
                  <Toggle
                    enabled={fps}
                    disabled={busy}
                    ariaLabel="Import frame-rate cap"
                    onChange={setFps}
                  />
                </Row>
              )}
              {preview.graphics_quality && (
                <Row label={`Graphics: ${preview.graphics_quality}`}>
                  <Toggle
                    enabled={graphics}
                    disabled={busy}
                    ariaLabel="Import graphics"
                    onChange={setGraphics}
                  />
                </Row>
              )}
              {!preview.sources.length &&
                preview.fps_cap == null &&
                !preview.graphics_quality && (
                  <p className="text-[12px] text-text-muted">
                    No supported settings found.
                  </p>
                )}
            </>
          )}
          <div className="flex justify-end gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() => setEnabled(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={busy}
              disabled={!Object.keys(patch).length}
              onClick={() => void apply()}
            >
              Import settings
            </Button>
          </div>
        </div>
      </Dialog>
    </Panel>
  );
}
