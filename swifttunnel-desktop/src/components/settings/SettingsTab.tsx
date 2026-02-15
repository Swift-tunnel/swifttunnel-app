import { type ReactNode } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useUpdaterStore } from "../../stores/updaterStore";
import { Toggle } from "../common/Toggle";
import { systemOpenUrl } from "../../lib/commands";
import type { AppSettings, UpdateChannel } from "../../lib/types";

declare const __APP_VERSION__: string;

export function SettingsTab() {
  const email = useAuthStore((s) => s.email);
  const isTester = useAuthStore((s) => s.isTester);
  const logout = useAuthStore((s) => s.logout);

  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const updaterStatus = useUpdaterStore((s) => s.status);
  const updaterVersion = useUpdaterStore((s) => s.availableVersion);
  const updaterProgress = useUpdaterStore((s) => s.progressPercent);
  const updaterLastChecked = useUpdaterStore((s) => s.lastChecked);
  const updaterError = useUpdaterStore((s) => s.error);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);
  const installUpdate = useUpdaterStore((s) => s.installUpdate);

  function set(partial: Partial<AppSettings>) {
    update(partial);
    save();
  }

  return (
    <div className="flex flex-col gap-6">
      {/* ── Account ── */}
      <Section title="Account">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex h-10 w-10 items-center justify-center rounded-full"
              style={{ backgroundColor: "var(--color-accent-primary-soft-20)" }}
            >
              <span className="text-sm font-medium text-accent-secondary">
                {email?.[0]?.toUpperCase() || "?"}
              </span>
            </div>
            <div>
              <div className="text-sm font-medium text-text-primary">
                {email || "Unknown"}
              </div>
              {isTester && (
                <span
                  className="text-[10px] font-medium"
                  style={{ color: "var(--color-accent-purple)" }}
                >
                  Tester
                </span>
              )}
            </div>
          </div>
          <button
            onClick={logout}
            className="rounded-[var(--radius-button)] border px-3 py-1.5 text-xs transition-colors"
            style={{
              borderColor: "var(--color-status-error-soft-20)",
              color: "var(--color-status-error)",
            }}
            onMouseEnter={(e) =>
              (e.currentTarget.style.backgroundColor =
                "var(--color-status-error-soft-10)")
            }
            onMouseLeave={(e) =>
              (e.currentTarget.style.backgroundColor = "transparent")
            }
          >
            Log Out
          </button>
        </div>
      </Section>

      {/* ── General ── */}
      <Section title="General">
        <Row label="Update Channel" desc="Stable for vetted releases, Live for pre-release">
          <div className="flex gap-1">
            {(["Stable", "Live"] as UpdateChannel[]).map((ch) => (
              <button
                key={ch}
                onClick={() => set({ update_channel: ch })}
                className="rounded px-3 py-1 text-xs transition-colors"
                style={{
                  backgroundColor:
                    settings.update_channel === ch
                      ? "var(--color-accent-primary)"
                      : "var(--color-bg-hover)",
                  color:
                    settings.update_channel === ch
                      ? "white"
                      : "var(--color-text-secondary)",
                }}
              >
                {ch}
              </button>
            ))}
          </div>
        </Row>
        <Row label="Auto Check Updates" desc="Check on app startup">
          <Toggle
            enabled={settings.update_settings.auto_check}
            onChange={(v) =>
              set({
                update_settings: {
                  ...settings.update_settings,
                  auto_check: v,
                },
              })
            }
          />
        </Row>
        <Row
          label="Close Behavior"
          desc="Closing the window sends SwiftTunnel to the tray. Use the tray menu Quit to exit."
        >
          <span className="text-xs text-text-muted">To tray</span>
        </Row>
        <Row label="Discord Rich Presence" desc="Show VPN status in Discord">
          <Toggle
            enabled={settings.enable_discord_rpc}
            onChange={(v) => set({ enable_discord_rpc: v })}
          />
        </Row>
      </Section>

      {/* ── Updates ── */}
      <Section title="Updates">
        <Row
          label="Update Status"
          desc={
            updaterStatus === "checking"
              ? "Checking for updates..."
              : updaterStatus === "up_to_date"
                ? "You are on the latest version"
                : updaterStatus === "update_available"
                  ? `Version ${updaterVersion} is available`
                  : updaterStatus === "installing"
                    ? `Installing update... ${updaterProgress}%`
                    : updaterStatus === "error"
                      ? updaterError || "Update check failed"
                      : "Not checked yet"
          }
        >
          <div className="flex items-center gap-2">
            <button
              onClick={() => void checkForUpdates(true)}
              disabled={updaterStatus === "checking" || updaterStatus === "installing"}
              className="rounded border border-border-subtle px-2.5 py-1 text-xs text-text-primary disabled:opacity-50"
            >
              Check Now
            </button>
            {updaterStatus === "update_available" && (
              <button
                onClick={() => void installUpdate()}
                className="rounded px-2.5 py-1 text-xs text-white"
                style={{ backgroundColor: "var(--color-accent-primary)" }}
              >
                Install
              </button>
            )}
          </div>
        </Row>
        <Row
          label="Last Checked"
          desc={
            updaterLastChecked
              ? new Date(updaterLastChecked * 1000).toLocaleString()
              : "Never"
          }
        >
          <span className="text-xs text-text-muted">Updater</span>
        </Row>
      </Section>

      {/* ── Experimental (tester-gated) ── */}
      {isTester && (
        <Section title="Experimental">
          <Row label="Practice Mode" desc="Add artificial latency for training">
            <Toggle
              enabled={settings.experimental_mode}
              onChange={(v) => set({ experimental_mode: v })}
            />
          </Row>
          {settings.experimental_mode && (
            <Row
              label="Artificial Latency"
              desc={`+${settings.artificial_latency_ms}ms added delay`}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-accent-secondary">
                  {settings.artificial_latency_ms}ms
                </span>
                <input
                  id="artificial-latency-slider"
                  type="range"
                  aria-label="Artificial latency"
                  min={0}
                  max={100}
                  step={5}
                  value={settings.artificial_latency_ms}
                  onChange={(e) =>
                    set({ artificial_latency_ms: Number(e.target.value) })
                  }
                  className="w-28 accent-accent-primary"
                />
              </div>
            </Row>
          )}
          <Row label="Custom Relay Server" desc="Override relay endpoint (host:port)">
            <input
              type="text"
              value={settings.custom_relay_server}
              onChange={(e) => set({ custom_relay_server: e.target.value })}
              placeholder="auto"
              className="w-40 rounded border bg-bg-input px-2 py-1 text-sm text-text-primary placeholder:text-text-dimmed focus:outline-none"
              style={{ borderColor: "var(--color-border-default)" }}
              onFocus={(e) =>
                (e.currentTarget.style.borderColor =
                  "var(--color-accent-primary)")
              }
              onBlur={(e) => {
                e.currentTarget.style.borderColor =
                  "var(--color-border-default)";
                save();
              }}
            />
          </Row>
        </Section>
      )}

      {/* ── About ── */}
      <Section title="About">
        <div className="flex items-center justify-between">
          <span className="text-sm text-text-secondary">
            SwiftTunnel Desktop v{__APP_VERSION__}
          </span>
          <div className="flex gap-3">
            <button
              onClick={() => systemOpenUrl("https://swifttunnel.net")}
              className="text-xs text-accent-secondary transition-opacity hover:opacity-80"
            >
              Website
            </button>
            <button
              onClick={() => systemOpenUrl("https://discord.gg/swifttunnel")}
              className="text-xs text-accent-secondary transition-opacity hover:opacity-80"
            >
              Discord
            </button>
          </div>
        </div>
      </Section>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section>
      <h3 className="mb-3 text-xs font-medium uppercase tracking-wider text-text-muted">
        {title}
      </h3>
      <div className="flex flex-col gap-2 rounded-[var(--radius-card)] border border-border-subtle bg-bg-card">
        {children}
      </div>
    </section>
  );
}

function Row({
  label,
  desc,
  children,
}: {
  label: string;
  desc: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <div className="flex flex-col gap-0.5">
        <span className="text-sm font-medium text-text-primary">{label}</span>
        <span className="text-xs text-text-muted">{desc}</span>
      </div>
      {children}
    </div>
  );
}
