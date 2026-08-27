import { useEffect, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import type { Config, GraphicsQuality } from "../../lib/types";
import { Choice, Group, PrimaryButton, Row, Switch } from "./ui";

/** The caps worth offering as buttons. Anything else is a rounding error. */
const FPS_PRESETS = [60, 120, 144, 165, 240] as const;

const QUALITY: { value: GraphicsQuality; label: string }[] = [
  { value: "Automatic", label: "Auto" },
  { value: "Level1", label: "Low" },
  { value: "Level10", label: "Max" },
];

/**
 * Lite's Roblox screen.
 *
 * The full app's Games page carries a per-game library, seven expandable
 * sections of Windows tuning, a RAM cleaner, a metrics header and a sticky
 * apply bar. Lite keeps the four things that are actually about Roblox: the
 * frame cap, the graphics level, fullscreen, and Ultraboost.
 *
 * Changes apply as they are made rather than through an apply bar. There is
 * one screen and four controls, so a staged draft would be more machinery than
 * the thing it stages.
 */
export function LiteRoblox() {
  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const updateConfig = useBoostStore((s) => s.updateConfig);
  const restartRoblox = useBoostStore((s) => s.restartRoblox);
  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const boostError = useBoostStore((s) => s.error);

  const [busy, setBusy] = useState(false);
  const roblox = settings.config.roblox_settings;

  // Cheap local call. 4s is enough for a "is Roblox open yet" signal, and it is
  // the only polling on this screen.
  useEffect(() => {
    void fetchMetrics();
    const id = window.setInterval(() => void fetchMetrics(), 4_000);
    return () => window.clearInterval(id);
  }, [fetchMetrics]);

  /**
   * Write one Roblox setting through the backend and into the settings file.
   *
   * The backend owns this: it edits Roblox's own ClientAppSettings and returns
   * the config it actually managed to apply, which is not always the one it
   * was handed. Storing the returned value rather than the requested one keeps
   * the UI honest about what is really set.
   */
  async function patch(next: Partial<typeof roblox>) {
    if (busy) return;
    setBusy(true);
    try {
      const draft: Config = {
        ...settings.config,
        roblox_settings: { ...roblox, ...next },
      };
      const applied = await updateConfig(JSON.stringify(draft));
      updateSettings({ config: applied });
      await saveSettings();
    } catch {
      // updateConfig already puts the reason in the store, and it is rendered
      // under the group below.
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Group title="Frame rate">
        <Row
          first
          label="Unlock frame rate"
          sub="Removes Roblox's 60 FPS cap"
          right={
            <Switch
              label="Unlock frame rate"
              checked={roblox.unlock_fps}
              disabled={busy}
              onChange={(next) => void patch({ unlock_fps: next })}
            />
          }
        />
        <Row
          label="Cap"
          disabled={!roblox.unlock_fps}
          right={
            <Choice
              value={roblox.target_fps}
              disabled={busy || !roblox.unlock_fps}
              options={FPS_PRESETS.map((fps) => ({
                value: fps,
                label: String(fps),
              }))}
              onChange={(next) => void patch({ target_fps: next })}
            />
          }
        />
      </Group>

      <Group title="Game">
        <Row
          first
          label="Graphics"
          right={
            <Choice
              value={roblox.graphics_quality}
              disabled={busy}
              options={QUALITY}
              onChange={(next) => void patch({ graphics_quality: next })}
            />
          }
        />
        <Row
          label="Ultraboost"
          sub="Strips post-processing for the most frames"
          right={
            <Switch
              label="Ultraboost"
              checked={roblox.ultraboost}
              disabled={busy}
              onChange={(next) => void patch({ ultraboost: next })}
            />
          }
        />
        <Row
          label="Launch fullscreen"
          right={
            <Switch
              label="Launch fullscreen"
              checked={roblox.window_fullscreen}
              disabled={busy}
              onChange={(next) => void patch({ window_fullscreen: next })}
            />
          }
        />
      </Group>

      {boostError && (
        <p
          className="mb-3 px-1 text-[10px] leading-snug"
          style={{ color: "var(--color-status-error)" }}
        >
          {boostError}
        </p>
      )}

      <PrimaryButton
        variant="outline"
        disabled={!robloxRunning || busy}
        onClick={() => void restartRoblox()}
      >
        {robloxRunning ? "Restart Roblox to apply" : "Roblox is not running"}
      </PrimaryButton>
      <p
        className="mt-2 px-1 text-[10px] leading-snug"
        style={{ color: "var(--color-text-dimmed)" }}
      >
        Settings are written straight to Roblox. A game already open keeps the
        values it launched with.
      </p>
    </>
  );
}
