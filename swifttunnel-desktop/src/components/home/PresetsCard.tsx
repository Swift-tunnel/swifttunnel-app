import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Button, Dialog, Spinner } from "../ui";
import { useToastStore } from "../../stores/toastStore";
import { usePresetStore, type SavedPreset } from "../../stores/presetStore";
import { presetSaveToDownloads, systemOpenUrl } from "../../lib/commands";
import {
  decodePreset,
  encodePreset,
  presetFileContents,
  presetFileName,
  type SwiftTunnelPreset,
} from "../../lib/presets";

export type PresetMode = "create" | "import" | null;

/** Short, human summary chips for a preset. */
function summarize(preset: SwiftTunnelPreset): string[] {
  const rs = preset.config.roblox_settings;
  const out: string[] = [
    `${preset.optimizations.length} opt${preset.optimizations.length === 1 ? "" : "s"}`,
    rs.unlock_fps
      ? `FPS ${rs.target_fps >= 1010 ? "uncapped" : rs.target_fps}`
      : "FPS cap",
  ];
  if (rs.ultraboost) out.push("FFlags");
  if (preset.config.overlay.enabled) out.push("Overlay");
  return out;
}

// ── Left-column panel: the switchable library ──

export function PresetsPanel({
  onCreate,
  onImport,
  animate,
  delay,
}: {
  onCreate: () => void;
  onImport: () => void;
  animate: boolean;
  delay: number;
}) {
  const presets = usePresetStore((s) => s.presets);
  const activeId = usePresetStore((s) => s.activeId);
  const applyingId = usePresetStore((s) => s.applyingId);
  const apply = usePresetStore((s) => s.apply);
  const remove = usePresetStore((s) => s.remove);

  const [shareId, setShareId] = useState<string | null>(null);
  const shareTarget = presets.find((p) => p.id === shareId) ?? null;

  return (
    <motion.div
      initial={animate ? { opacity: 0, y: 12 } : false}
      animate={animate ? { opacity: 1, y: 0 } : undefined}
      transition={{ delay, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-2.5"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-semibold text-text-primary">
          Your presets
        </span>
        {presets.length > 0 && (
          <span className="text-[10.5px] text-text-dimmed">
            {presets.length} saved
          </span>
        )}
      </div>

      {presets.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2.5 rounded-[12px] surface-card px-6 py-8 text-center">
          <span className="icon-orb flex h-11 w-11 items-center justify-center">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent-primary)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l9 5-9 5-9-5 9-5z" />
              <path d="M3 13l9 5 9-5" />
            </svg>
          </span>
          <div className="text-[13px] font-semibold text-text-primary">
            No presets yet
          </div>
          <p className="max-w-[300px] text-[11.5px] leading-relaxed text-text-muted">
            Save your current setup as a preset, or import a config someone
            shared — then switch between them anytime.
          </p>
          <div className="mt-1 flex gap-2">
            <Button variant="primary" size="sm" onClick={onCreate}>
              Create preset
            </Button>
            <Button variant="secondary" size="sm" onClick={onImport}>
              Import config
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {presets.map((p) => (
            <PresetRow
              key={p.id}
              preset={p}
              active={p.id === activeId}
              applying={applyingId === p.id}
              anyApplying={applyingId !== null}
              onApply={() => void apply(p.id)}
              onShare={() => setShareId(p.id)}
              onDelete={() => remove(p.id)}
            />
          ))}
          <div className="mt-1 flex gap-2">
            <Button variant="secondary" size="sm" onClick={onCreate}>
              Create preset
            </Button>
            <Button variant="ghost" size="sm" onClick={onImport}>
              Import config
            </Button>
          </div>
        </div>
      )}

      <Dialog
        open={!!shareTarget}
        onClose={() => setShareId(null)}
        title="Share preset"
        description={shareTarget?.name}
        maxWidth={540}
      >
        {shareTarget && <PresetShare preset={shareTarget} />}
      </Dialog>
    </motion.div>
  );
}

function PresetRow({
  preset,
  active,
  applying,
  anyApplying,
  onApply,
  onShare,
  onDelete,
}: {
  preset: SavedPreset;
  active: boolean;
  applying: boolean;
  anyApplying: boolean;
  onApply: () => void;
  onShare: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      className="flex items-center gap-2.5 rounded-[10px] px-3 py-2.5"
      style={{
        backgroundColor: "var(--color-bg-base)",
        boxShadow: active
          ? "inset 0 0 0 1px var(--color-accent-primary-soft-20)"
          : "inset 0 0 0 1px var(--color-border-subtle)",
      }}
    >
      <button
        type="button"
        onClick={onApply}
        disabled={anyApplying}
        className="min-w-0 flex-1 text-left"
      >
        <div className="flex items-center gap-2">
          <span className="truncate text-[12.5px] font-semibold text-text-primary">
            {preset.name}
          </span>
          {active && (
            <span
              className="shrink-0 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide"
              style={{
                backgroundColor: "var(--color-accent-primary-soft-15)",
                color: "var(--color-accent-primary)",
              }}
            >
              Active
            </span>
          )}
        </div>
        <div className="truncate text-[10.5px] text-text-muted">
          {summarize(preset).join(" · ")}
        </div>
      </button>

      {applying ? (
        <Spinner size={15} color="var(--color-text-muted)" />
      ) : (
        !active && (
          <button
            type="button"
            onClick={onApply}
            disabled={anyApplying}
            className="shrink-0 rounded-[7px] px-2.5 py-1 text-[10.5px] font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
            style={{ backgroundColor: "var(--color-bg-card)" }}
          >
            Switch
          </button>
        )
      )}

      <IconBtn onClick={onShare} label="Share preset">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
          <path d="M4 12v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6" />
          <path d="M16 6l-4-4-4 4M12 2v13" />
        </svg>
      </IconBtn>
      <IconBtn onClick={onDelete} label="Delete preset">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
          <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
        </svg>
      </IconBtn>
    </div>
  );
}

function IconBtn({
  onClick,
  label,
  children,
}: {
  onClick: () => void;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      className="shrink-0 rounded-[6px] p-1 text-text-dimmed transition-colors hover:text-text-primary"
    >
      {children}
    </button>
  );
}

// ── Shared "share this preset" block (code + copy + download) ──

function PresetShare({ preset }: { preset: SwiftTunnelPreset }) {
  const code = useMemo(() => encodePreset(preset), [preset]);
  const [savedFolder, setSavedFolder] = useState<string | null>(null);
  const addToast = useToastStore((s) => s.addToast);

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(code);
      addToast({ type: "success", message: "Config copied to clipboard" });
    } catch {
      addToast({
        type: "error",
        message: "Couldn't copy automatically — select the config and copy it.",
      });
    }
  }

  async function download() {
    try {
      const res = await presetSaveToDownloads(
        presetFileName(preset.name),
        presetFileContents(preset),
      );
      setSavedFolder(res.folder_path);
      addToast({ type: "success", message: "Config saved as a .txt file" });
    } catch {
      addToast({
        type: "error",
        message:
          "Couldn't save the config file. Make sure the folder isn't read-only, then try again.",
      });
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5">
        {summarize(preset).map((c) => (
          <span
            key={c}
            className="rounded-full px-2.5 py-1 text-[10.5px] font-medium text-text-secondary"
            style={{ backgroundColor: "var(--color-bg-base)" }}
          >
            {c}
          </span>
        ))}
      </div>
      <textarea
        readOnly
        value={code}
        onFocus={(e) => e.currentTarget.select()}
        rows={7}
        className="resize-none rounded-[9px] px-3 py-2 font-mono text-[11px] leading-relaxed text-text-secondary outline-none"
        style={{
          backgroundColor: "var(--color-bg-base)",
          border: "1px solid var(--color-border-subtle)",
          whiteSpace: "pre",
          overflowX: "auto",
        }}
      />
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" size="sm" onClick={copyCode}>
          Copy config
        </Button>
        <Button variant="secondary" size="sm" onClick={download}>
          Download .txt
        </Button>
        {savedFolder && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void systemOpenUrl(savedFolder)}
          >
            Show file
          </Button>
        )}
      </div>
      <p className="text-[11px] text-text-muted">
        Share the config or the .txt — it's just settings (no account or region
        data), so it's safe to send. Anyone can import it to get this exact setup.
      </p>
    </div>
  );
}

// ── Dialogs (create + import), driven from Home ──

export function PresetsDialog({
  mode,
  onClose,
}: {
  mode: PresetMode;
  onClose: () => void;
}) {
  return (
    <>
      <CreateDialog open={mode === "create"} onClose={onClose} />
      <ImportDialog open={mode === "import"} onClose={onClose} />
    </>
  );
}

function CreateDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [name, setName] = useState("");
  const [created, setCreated] = useState<SavedPreset | null>(null);
  const createFromCurrent = usePresetStore((s) => s.createFromCurrent);
  const addToast = useToastStore((s) => s.addToast);

  useEffect(() => {
    if (open) {
      setName("");
      setCreated(null);
    }
  }, [open]);

  function doCreate() {
    const p = createFromCurrent(name);
    setCreated(p);
    addToast({ type: "success", message: `Preset "${p.name}" saved` });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Create a preset"
      description="Save your current setup — switch back to it anytime, or share it."
      maxWidth={540}
    >
      {!created ? (
        <div className="flex flex-col gap-4">
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-medium text-text-secondary">
              Preset name
            </span>
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doCreate()}
              placeholder="e.g. My Roblox Setup"
              className="rounded-[9px] px-3 py-2 text-[13px] text-text-primary outline-none"
              style={{
                backgroundColor: "var(--color-bg-base)",
                border: "1px solid var(--color-border-subtle)",
              }}
            />
          </label>
          <p className="text-[11.5px] leading-relaxed text-text-muted">
            Captures your Roblox settings, overlay, applied optimizations and
            network/system tweaks. Your region, relay and adapter are never
            included.
          </p>
          <Button variant="primary" onClick={doCreate}>
            Create preset
          </Button>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <PresetShare preset={created} />
          <div className="flex justify-end">
            <Button variant="secondary" size="sm" onClick={onClose}>
              Done
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function ImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const addImported = usePresetStore((s) => s.addImported);
  const apply = usePresetStore((s) => s.apply);

  useEffect(() => {
    if (open) {
      setText("");
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const preview = useMemo<SwiftTunnelPreset | null>(() => {
    if (!text.trim()) return null;
    try {
      return decodePreset(text);
    } catch {
      return null;
    }
  }, [text]);

  async function doImport() {
    let preset: SwiftTunnelPreset;
    try {
      preset = decodePreset(text);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    setBusy(true);
    setError(null);
    const saved = addImported(preset);
    await apply(saved.id);
    setBusy(false);
    onClose();
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Import a config"
      description="Paste a shared config (or a .txt's contents). It's saved and applied."
      maxWidth={540}
    >
      <div className="flex flex-col gap-4">
        <textarea
          autoFocus
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setError(null);
          }}
          placeholder="Paste a SwiftTunnel config here…"
          rows={6}
          className="resize-none rounded-[9px] px-3 py-2 font-mono text-[11px] leading-relaxed text-text-primary outline-none"
          style={{
            backgroundColor: "var(--color-bg-base)",
            border: `1px solid ${error ? "var(--color-latency-bad)" : "var(--color-border-subtle)"}`,
            whiteSpace: "pre",
            overflowX: "auto",
          }}
        />

        {error && (
          <p className="text-[11.5px]" style={{ color: "var(--color-latency-bad)" }}>
            {error}
          </p>
        )}

        {preview && !error && (
          <div
            className="rounded-[10px] p-3"
            style={{ backgroundColor: "var(--color-bg-base)" }}
          >
            <div className="text-[12px] font-semibold text-text-primary">
              {preview.name}
            </div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {summarize(preview).map((c) => (
                <span
                  key={c}
                  className="rounded-full px-2.5 py-0.5 text-[10.5px] font-medium text-text-secondary"
                  style={{ backgroundColor: "var(--color-bg-card)" }}
                >
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={doImport}
            disabled={busy || !preview}
          >
            {busy ? (
              <>
                <Spinner size={13} color="currentColor" />
                Applying…
              </>
            ) : (
              "Import & apply"
            )}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
