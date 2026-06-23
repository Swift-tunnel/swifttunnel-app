import { type ReactNode, useEffect, useRef, useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useUpdaterStore } from "../../stores/updaterStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useToastStore } from "../../stores/toastStore";
import {
  Toggle,
  Button,
  Chip,
  Row,
  Segmented,
  Tooltip,
  InfoIcon,
  SectionHeader,
  Slider,
  Dialog,
} from "../ui";
import {
  systemOpenUrl,
  systemUninstall,
} from "../../lib/commands";
import { SupportToolsSection } from "../support/SupportToolsSection";
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

  const vpnState = useVpnStore((s) => s.state);
  const vpnDiagnostics = useVpnStore((s) => s.diagnostics);
  const fetchVpnDiagnostics = useVpnStore((s) => s.fetchDiagnostics);

  const addToast = useToastStore((s) => s.addToast);

  const [isUninstalling, setIsUninstalling] = useState(false);
  const [uninstallError, setUninstallError] = useState<string | null>(null);
  const [confirmUninstallOpen, setConfirmUninstallOpen] = useState(false);
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const routeSourceLabel = (() => {
    switch (vpnDiagnostics?.route_resolution_source) {
      case "game_route":
        return "Game route";
      case "internet_fallback":
        return "Internet fallback";
      case "native_table_fallback":
        return "Native route table fallback";
      case "powershell_fallback":
        return "PowerShell fallback";
      default:
        return "Not resolved";
    }
  })();
  const routeAssistDisabledByPartial = settings.enable_partial_country_ban;

  function set(partial: Partial<AppSettings>, options?: { toast?: boolean }) {
    update(partial);
    save();
    if (options?.toast !== false) {
      addToast({ type: "success", message: "Settings saved" });
    }
  }

  function setQuietDebounced(partial: Partial<AppSettings>) {
    update(partial);
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }
    saveTimeoutRef.current = setTimeout(() => {
      saveTimeoutRef.current = null;
      void save();
    }, 500);
  }

  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
        void save();
      }
    };
  }, [save]);

  useEffect(() => {
    void fetchVpnDiagnostics();
    if (vpnState !== "connected") return;
    const id = setInterval(() => {
      void fetchVpnDiagnostics();
    }, 3000);
    return () => clearInterval(id);
  }, [fetchVpnDiagnostics, vpnState]);

  const updateLabel = (() => {
    switch (updaterStatus) {
      case "checking":
        return "Checking…";
      case "installing":
        return "Installing";
      case "update_available":
        return `v${updaterVersion} ready`;
      case "up_to_date":
        return "Up to date";
      case "error":
        return "Update error";
      default:
        return "Not checked";
    }
  })();
  const updateColor =
    updaterStatus === "error"
      ? "var(--color-status-error)"
      : updaterStatus === "update_available"
        ? "var(--color-accent-primary)"
        : updaterStatus === "up_to_date"
          ? "var(--color-status-connected)"
          : "var(--color-text-muted)";

  return (
    <div className="flex w-full flex-col gap-4 pb-6">
      {/* ── Account hero ── */}
      <section className="relative overflow-hidden rounded-[var(--radius-card)] surface-card">
        <div
          className="dot-grid pointer-events-none absolute inset-x-0 top-0 h-[110px]"
          style={{ opacity: 0.45 }}
        />

        <div className="relative flex items-center gap-4 px-6 pb-5 pt-6">
          <div
            className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-[17px] font-semibold"
            style={{
              background:
                "linear-gradient(135deg, var(--color-bg-elevated), var(--color-bg-active))",
              color: "var(--color-text-primary)",
              border: "1px solid var(--color-border-default)",
              boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)",
            }}
          >
            {email?.[0]?.toUpperCase() || "?"}
          </div>

          <div className="min-w-0 flex-1">
            <span className="eyebrow">Signed in as</span>
            <div className="mt-1.5 flex items-center gap-2">
              <span
                className="truncate text-[17px] font-semibold leading-none text-text-primary"
                style={{ letterSpacing: "-0.018em" }}
              >
                {email || "Unknown"}
              </span>
              {isTester && (
                <Chip tone="accent" uppercase size="xs">
                  Tester
                </Chip>
              )}
            </div>
          </div>

          <Button variant="destructive" size="sm" onClick={logout}>
            Log out
          </Button>
        </div>

        {/* Stats strip */}
        <div
          className="relative grid grid-cols-3 border-t"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          <HeroStat label="Version" value={`v${__APP_VERSION__}`} divider />
          <HeroStat label="Channel" value={settings.update_channel} divider />
          <div className="flex flex-col gap-1.5 px-6 py-3.5">
            <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
              Updates
            </span>
            <span
              className="pill-base self-start"
              style={{
                backgroundColor: `${updateColor}1a`,
                color: updateColor,
                border: `1px solid ${updateColor}30`,
              }}
            >
              {updateLabel}
            </span>
          </div>
        </div>
      </section>

      {/* General */}
      <Section title="General">
        <Row
          label="Run on startup"
          desc="Launch SwiftTunnel when you sign in to Windows"
        >
          <Toggle
            enabled={settings.run_on_startup}
            ariaLabel="Run on startup"
            onChange={(v) => set({ run_on_startup: v })}
          />
        </Row>
        <Row
          label="Auto-reconnect tunnel"
          desc="Reconnect after restart if last session was connected"
        >
          <Toggle
            enabled={settings.auto_reconnect}
            ariaLabel="Auto-reconnect tunnel"
            onChange={(v) => set({ auto_reconnect: v })}
          />
        </Row>
        <Row
          label="Discord Rich Presence"
          desc="Show tunnel status in your Discord profile"
        >
          <Toggle
            enabled={settings.enable_discord_rpc}
            ariaLabel="Discord Rich Presence"
            onChange={(v) => set({ enable_discord_rpc: v })}
          />
        </Row>
      </Section>

      {/* Tunnel */}
      <Section title="Tunnel">
        <Row
          label="Roblox Route Assist"
          desc={
            routeAssistDisabledByPartial
              ? "Disabled while Partial Bypass is active"
              : "Lands you in game servers near your tunneled region"
          }
          tooltip={
            <Tooltip
              content={
                routeAssistDisabledByPartial
                  ? "Partial Bypass already routes the Roblox join path and keeps gameplay direct."
                  : "Routes Roblox matchmaking/login traffic through the relay so Roblox places you near your tunneled region. For blocked countries, use the Bypass toggles in Optimize instead."
              }
            >
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          }
        >
          <Toggle
            enabled={
              settings.enable_api_tunneling && !routeAssistDisabledByPartial
            }
            disabled={routeAssistDisabledByPartial}
            ariaLabel="Roblox Route Assist"
            onChange={(v) => set({ enable_api_tunneling: v })}
          />
        </Row>

        <details className="group/diag">
          <summary
            className="flex cursor-pointer items-center gap-2 px-3.5 py-2.5 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-muted transition-colors hover:text-text-secondary"
            style={{ listStyle: "none" }}
          >
            <svg
              width="10"
              height="10"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="transition-transform duration-150 group-open/diag:rotate-90"
            >
              <path d="M9 18l6-6-6-6" />
            </svg>
            Adapter diagnostics
          </summary>
          <div
            className="mx-3.5 mb-3 grid grid-cols-2 gap-x-4 gap-y-2 rounded-[7px] px-3.5 py-3 text-[10.5px]"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <DiagItem label="State" value={vpnState} />
            <DiagItem label="Adapter" value={vpnDiagnostics?.adapter_name} />
            <DiagItem
              label="GUID"
              value={vpnDiagnostics?.adapter_guid}
              mono
            />
            <DiagItem
              label="Selected ifIndex"
              value={vpnDiagnostics?.selected_if_index}
              mono
            />
            <DiagItem
              label="Resolved ifIndex"
              value={vpnDiagnostics?.resolved_if_index}
              mono
            />
            <DiagItem label="Route source" value={routeSourceLabel} />
            <DiagItem
              label="Route target"
              value={vpnDiagnostics?.route_resolution_target_ip}
              mono
            />
            <DiagItem
              label="Has route"
              value={vpnDiagnostics?.has_default_route ? "yes" : "no"}
            />
            <DiagItem
              label="Manual binding"
              value={vpnDiagnostics?.manual_binding_active ? "yes" : "no"}
            />
            <DiagItem
              label="Cached override"
              value={vpnDiagnostics?.cached_override_used ? "yes" : "no"}
            />
            <DiagItem
              label="Binding stage"
              value={vpnDiagnostics?.binding_stage}
            />
            <DiagItem
              label="Validation"
              value={vpnDiagnostics?.last_validation_result}
            />
            <div className="col-span-2">
              <DiagItem
                label="Binding reason"
                value={vpnDiagnostics?.binding_reason}
              />
            </div>
            <DiagItem
              label="Packets"
              mono
              value={`${vpnDiagnostics?.packets_tunneled ?? 0} tunneled / ${vpnDiagnostics?.packets_bypassed ?? 0} bypassed`}
            />
          </div>
        </details>
      </Section>

      {/* Updates */}
      <Section title="Updates">
        <Row
          label="Update channel"
          desc="Stable for vetted releases, Live for pre-release"
        >
          <Segmented
            options={["Stable", "Live"] as UpdateChannel[]}
            value={settings.update_channel}
            onChange={(ch) => set({ update_channel: ch })}
          />
        </Row>
        <Row
          label="Auto update"
          desc="Automatically check for updates on startup"
        >
          <Toggle
            enabled={settings.update_settings.auto_check}
            ariaLabel="Auto update"
            onChange={(v) =>
              set({
                update_settings: { ...settings.update_settings, auto_check: v },
              })
            }
          />
        </Row>

        <div className="px-3.5 py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2.5">
              <span
                className="shrink-0 rounded-[4px] px-1.5 py-1 font-mono text-[11px] font-semibold leading-none"
                style={{
                  backgroundColor: "var(--color-bg-elevated)",
                  color: "var(--color-text-primary)",
                  border: "1px solid var(--color-border-subtle)",
                }}
              >
                v{__APP_VERSION__}
              </span>
              {updaterStatus === "update_available" && (
                <>
                  <svg
                    width="11"
                    height="11"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="var(--color-text-dimmed)"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="shrink-0"
                  >
                    <path d="M5 12h14M12 5l7 7-7 7" />
                  </svg>
                  <span
                    className="shrink-0 rounded-[4px] px-1.5 py-1 font-mono text-[11px] font-semibold leading-none"
                    style={{
                      backgroundColor: "var(--color-accent-primary-soft-12)",
                      color: "var(--color-text-primary)",
                      border: "1px solid var(--color-accent-primary-soft-20)",
                    }}
                  >
                    v{updaterVersion}
                  </span>
                </>
              )}
              <UpdaterStatusLine
                status={updaterStatus}
                version={updaterVersion}
                error={updaterError}
              />
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {updaterStatus === "update_available" && (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => void installUpdate()}
                >
                  Update now
                </Button>
              )}
              {updaterStatus === "error" ? (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void checkForUpdates(true)}
                  style={{
                    color: "var(--color-status-error)",
                    border: "1px solid var(--color-status-error-soft-20)",
                  }}
                >
                  Retry
                </Button>
              ) : (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => void checkForUpdates(true)}
                  disabled={
                    updaterStatus === "checking" ||
                    updaterStatus === "installing"
                  }
                >
                  Check now
                </Button>
              )}
            </div>
          </div>

          {updaterStatus === "installing" && (
            <div className="mt-3">
              <div
                className="h-1 w-full overflow-hidden rounded-full"
                style={{ backgroundColor: "var(--color-bg-elevated)" }}
              >
                <div
                  className="h-full rounded-full transition-all duration-300 ease-out"
                  style={{
                    width: `${updaterProgress}%`,
                    backgroundColor: "var(--color-accent-primary)",
                  }}
                />
              </div>
              <div className="mt-1 text-right font-mono text-[10px] text-text-dimmed">
                {updaterProgress}%
              </div>
            </div>
          )}

          <div className="mt-2.5 font-mono text-[10px] text-text-dimmed">
            Last checked:{" "}
            {updaterLastChecked
              ? new Date(updaterLastChecked * 1000).toLocaleString()
              : "Never"}
          </div>
        </div>
      </Section>

      {/* Experimental */}
      {isTester && (
        <Section title="Experimental" tag="Tester">
          <div>
          <Row
            label="Practice mode"
            desc="Add artificial latency for training"
          >
            <Toggle
              enabled={settings.experimental_mode}
              ariaLabel="Practice mode"
              onChange={(v) => set({ experimental_mode: v })}
            />
          </Row>
          {settings.experimental_mode && (
            <SubRow>
              <div className="flex items-center justify-between">
                <span className="text-[11.5px] text-text-muted">
                  Artificial latency
                </span>
                <div className="flex items-center gap-3">
                  <span className="lcd-readout text-[12px] font-semibold text-text-primary">
                    +{settings.artificial_latency_ms}ms
                  </span>
                  <div className="w-32">
                    <Slider
                      ariaLabel="Artificial latency"
                      min={0}
                      max={100}
                      step={5}
                      value={settings.artificial_latency_ms}
                      onChange={(v) =>
                        setQuietDebounced({ artificial_latency_ms: v })
                      }
                    />
                  </div>
                </div>
              </div>
            </SubRow>
          )}
          </div>
          <Row
            label="Custom relay server"
            desc="Override relay endpoint (host:port)"
          >
            <input
              type="text"
              value={settings.custom_relay_server}
              onChange={(e) =>
                setQuietDebounced({ custom_relay_server: e.target.value })
              }
              placeholder="auto"
              className="w-40 rounded-[var(--radius-input)] px-2.5 py-1.5 font-mono text-[12px] outline-none transition-colors focus:border-[color:var(--color-border-strong)]"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                border: "1px solid var(--color-border-default)",
                color: "var(--color-text-primary)",
              }}
              onBlur={() => save()}
            />
          </Row>
        </Section>
      )}

      <SupportToolsSection />

      {/* About */}
      <Section title="About">
        <Row
          label="SwiftTunnel Desktop"
          desc={`Version ${__APP_VERSION__}`}
        >
          <div className="flex items-center gap-2">
            <LinkButton onClick={() => systemOpenUrl("https://swifttunnel.net")}>
              Website
            </LinkButton>
            <LinkButton
              onClick={() => systemOpenUrl("https://discord.gg/swifttunnel")}
            >
              Discord
            </LinkButton>
          </div>
        </Row>
        <div>
        <Row
          label="Uninstall SwiftTunnel"
          desc="Remove app and revert all system changes"
        >
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setConfirmUninstallOpen(true)}
            disabled={isUninstalling}
            loading={isUninstalling}
          >
            {isUninstalling ? "Uninstalling" : "Uninstall"}
          </Button>
        </Row>
        {uninstallError && (
          <SubRow>
            <div className="text-[11px] text-status-error">
              {uninstallError}
            </div>
          </SubRow>
        )}
        </div>
      </Section>
      <Dialog
        open={confirmUninstallOpen}
        onClose={() => {
          if (!isUninstalling) setConfirmUninstallOpen(false);
        }}
        title="Uninstall SwiftTunnel?"
        description="This removes the app and attempts to revert SwiftTunnel system changes."
      >
        <div className="flex flex-col gap-4">
          <p className="text-[12px] leading-relaxed text-text-secondary">
            SwiftTunnel will run its uninstall cleanup, including driver,
            optimizer, and Roblox configuration cleanup. This cannot be undone
            from inside the app.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setConfirmUninstallOpen(false)}
              disabled={isUninstalling}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={async () => {
                setIsUninstalling(true);
                setUninstallError(null);
                try {
                  await systemUninstall();
                  setIsUninstalling(false);
                  setConfirmUninstallOpen(false);
                } catch (e) {
                  setUninstallError(String(e));
                  setIsUninstalling(false);
                  setConfirmUninstallOpen(false);
                }
              }}
              disabled={isUninstalling}
              loading={isUninstalling}
            >
              Uninstall
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

// ── Sub-components ──

function Section({
  title,
  tag,
  children,
}: {
  title: string;
  tag?: string;
  children: ReactNode;
}) {
  return (
    <section>
      <SectionHeader label={title} tag={tag} />
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {children}
      </div>
    </section>
  );
}

/** Indented follow-up content that belongs to the row above it. */
function SubRow({ children }: { children: ReactNode }) {
  return <div className="px-3.5 pb-3 pt-0.5">{children}</div>;
}

function HeroStat({
  label,
  value,
  divider,
}: {
  label: string;
  value: string;
  divider?: boolean;
}) {
  return (
    <div
      className="flex flex-col gap-1 px-6 py-3.5"
      style={{
        borderRight: divider
          ? "1px solid var(--color-border-subtle)"
          : undefined,
      }}
    >
      <span className="text-[10px] font-medium uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span className="lcd-readout text-[15px] font-medium leading-none text-text-primary">
        {value}
      </span>
    </div>
  );
}

function DiagItem({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
        {label}
      </span>
      <span
        className={`break-all text-text-primary ${mono ? "font-mono text-[10px]" : "text-[11px]"}`}
      >
        {value ?? "n/a"}
      </span>
    </div>
  );
}

function LinkButton({
  onClick,
  children,
}: {
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-[5px] px-2.5 py-1.5 text-[11.5px] font-medium transition-colors hover:bg-bg-hover"
      style={{
        color: "var(--color-text-secondary)",
        border: "1px solid var(--color-border-subtle)",
        backgroundColor: "var(--color-bg-elevated)",
      }}
    >
      {children}
      <svg
        width="10"
        height="10"
        viewBox="0 0 24 24"
        fill="none"
        stroke="var(--color-text-dimmed)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M7 17L17 7M7 7h10v10" />
      </svg>
    </button>
  );
}

function UpdaterStatusLine({
  status,
  version,
  error,
}: {
  status: string;
  version: string | null;
  error: string | null;
}) {
  const color =
    status === "checking" || status === "installing"
      ? "var(--color-accent-primary)"
      : status === "up_to_date"
        ? "var(--color-status-connected)"
        : status === "update_available"
          ? "var(--color-accent-primary)"
          : status === "error"
            ? "var(--color-status-error)"
            : "var(--color-text-muted)";
  const text =
    status === "checking"
      ? "Checking for updates…"
      : status === "up_to_date"
        ? "You're up to date"
        : status === "update_available"
          ? "Update available"
          : status === "installing"
            ? `Installing v${version}…`
            : status === "error"
              ? error || "Update check failed"
              : "Not checked yet";

  return (
    <div className="flex min-w-0 items-center gap-1.5">
      {(status === "checking" || status === "installing") && (
        <svg
          className="h-3 w-3 shrink-0 animate-spin"
          viewBox="0 0 24 24"
          fill="none"
        >
          <circle
            cx="12"
            cy="12"
            r="10"
            stroke={color}
            strokeWidth="2.5"
            strokeDasharray="50"
            strokeLinecap="round"
          />
        </svg>
      )}
      {status === "up_to_date" && (
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="shrink-0"
        >
          <path d="M20 6 9 17l-5-5" />
        </svg>
      )}
      {status === "error" && (
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="shrink-0"
        >
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      )}
      <span
        className="truncate text-[11.5px] font-medium"
        style={{ color }}
        title={status === "error" && error ? error : undefined}
      >
        {text}
      </span>
    </div>
  );
}
