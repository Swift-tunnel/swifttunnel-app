import { type ReactNode, useEffect, useState } from "react";
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
} from "../ui";
import {
  settingsGenerateNetworkDiagnosticsBundle,
  systemOpenUrl,
  systemUninstall,
  vpnListNetworkAdapters,
} from "../../lib/commands";
import type {
  AppSettings,
  NetworkAdapterInfo,
  UpdateChannel,
} from "../../lib/types";

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

  const [isGeneratingDiagnostics, setIsGeneratingDiagnostics] = useState(false);
  const [diagnosticsPath, setDiagnosticsPath] = useState<string | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);

  const [networkAdapters, setNetworkAdapters] = useState<
    NetworkAdapterInfo[] | null
  >(null);
  const [networkAdaptersLoading, setNetworkAdaptersLoading] = useState(false);
  const [networkAdaptersError, setNetworkAdaptersError] = useState<string | null>(
    null,
  );

  const [isUninstalling, setIsUninstalling] = useState(false);
  const [uninstallError, setUninstallError] = useState<string | null>(null);

  const adapterBindingMode = settings.adapter_binding_mode;
  const manualAdapterBinding = adapterBindingMode === "manual";

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

  function set(partial: Partial<AppSettings>) {
    update(partial);
    save();
    addToast({ type: "success", message: "Settings saved" });
  }

  useEffect(() => {
    let cancelled = false;
    setNetworkAdaptersLoading(true);
    setNetworkAdaptersError(null);

    vpnListNetworkAdapters()
      .then((adapters) => {
        if (cancelled) return;
        setNetworkAdapters(adapters);
      })
      .catch((e) => {
        if (cancelled) return;
        setNetworkAdapters(null);
        setNetworkAdaptersError(String(e));
      })
      .finally(() => {
        if (cancelled) return;
        setNetworkAdaptersLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void fetchVpnDiagnostics();
    if (vpnState !== "connected") return;
    const id = setInterval(() => {
      void fetchVpnDiagnostics();
    }, 3000);
    return () => clearInterval(id);
  }, [fetchVpnDiagnostics, vpnState]);

  async function generateDiagnosticsBundle() {
    setIsGeneratingDiagnostics(true);
    setDiagnosticsError(null);

    try {
      const response = await settingsGenerateNetworkDiagnosticsBundle();
      setDiagnosticsPath(response.file_path);
      addToast({ type: "success", message: "Diagnostics bundle generated" });

      try {
        await systemOpenUrl(response.folder_path);
      } catch (openError) {
        setDiagnosticsError(
          `Bundle generated, but failed to open folder: ${String(openError)}`,
        );
      }
    } catch (e) {
      setDiagnosticsError(String(e));
    } finally {
      setIsGeneratingDiagnostics(false);
    }
  }

  const sortedAdapters = (networkAdapters || []).slice().sort((a, b) => {
    if (a.is_default_route !== b.is_default_route)
      return a.is_default_route ? -1 : 1;
    if (a.is_up !== b.is_up) return a.is_up ? -1 : 1;
    const kindPriority = (k: string) => {
      switch (k) {
        case "ethernet":
          return 0;
        case "wifi":
          return 1;
        case "ppp":
          return 2;
        case "tunnel":
          return 3;
        case "loopback":
          return 4;
        default:
          return 5;
      }
    };
    const ap = kindPriority(a.kind);
    const bp = kindPriority(b.kind);
    if (ap !== bp) return ap - bp;
    const an = (a.friendly_name || a.description || a.guid).toLowerCase();
    const bn = (b.friendly_name || b.description || b.guid).toLowerCase();
    return an.localeCompare(bn);
  });

  const adapterMissing =
    !networkAdaptersError &&
    manualAdapterBinding &&
    settings.preferred_physical_adapter_guid &&
    networkAdapters &&
    !networkAdapters.some(
      (a) => a.guid === settings.preferred_physical_adapter_guid,
    );

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
        return "Idle";
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
    <div className="flex w-full flex-col gap-5 pb-4">
      {/* ── Hero ── */}
      <section className="flex items-start justify-between gap-6 pt-1">
        <div className="min-w-0 flex-1">
          <div className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-text-muted">
            Account
          </div>
          <div className="mt-2.5 flex items-center gap-2.5">
            <div
              className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[12px] font-semibold"
              style={{
                backgroundColor: "var(--color-bg-hover)",
                color: "var(--color-text-primary)",
                border: "1px solid var(--color-border-default)",
              }}
            >
              {email?.[0]?.toUpperCase() || "?"}
            </div>
            <span
              className="truncate text-[22px] font-semibold leading-none tracking-[-0.015em]"
              style={{ color: "var(--color-text-primary)" }}
            >
              {email || "Unknown"}
            </span>
            {isTester && (
              <Chip tone="neutral" uppercase size="xs">
                Tester
              </Chip>
            )}
          </div>
          <div className="mt-3 flex items-baseline gap-4">
            <div className="flex items-baseline gap-1.5">
              <span
                className="font-mono text-[22px] font-medium leading-none tabular-nums"
                style={{ color: "var(--color-text-primary)" }}
              >
                v{__APP_VERSION__}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: updateColor }}
              />
              <span
                className="text-[10.5px] font-semibold uppercase tracking-[0.12em]"
                style={{ color: updateColor }}
              >
                {updateLabel}
              </span>
            </div>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={logout}
          style={{
            color: "var(--color-status-error)",
            border: "1px solid var(--color-status-error-soft-20)",
          }}
        >
          Log out
        </Button>
      </section>

      {/* General */}
      <Section title="General">
        <Row
          label="Run on startup"
          desc="Launch SwiftTunnel when you sign in to Windows"
        >
          <Toggle
            enabled={settings.run_on_startup}
            onChange={(v) => set({ run_on_startup: v })}
          />
        </Row>
        <Row
          label="Auto-reconnect tunnel"
          desc="Reconnect after restart if last session was connected"
        >
          <Toggle
            enabled={settings.auto_reconnect}
            onChange={(v) => set({ auto_reconnect: v })}
          />
        </Row>
        <Row
          label="Discord Rich Presence"
          desc="Show tunnel status in your Discord profile"
        >
          <Toggle
            enabled={settings.enable_discord_rpc}
            onChange={(v) => set({ enable_discord_rpc: v })}
          />
        </Row>
      </Section>

      {/* Tunnel */}
      <Section title="Tunnel">
        <Row
          label="Adapter selection"
          desc={
            manualAdapterBinding
              ? "Manual — locked to a specific adapter"
              : "Smart Auto — follows active route, rebinds on network change"
          }
          tooltip={
            <Tooltip content="Smart Auto detects your active adapter from the OS routing table and rebinds automatically on network changes. Manual pins a specific adapter.">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          }
        >
          <Segmented
            options={[
              { value: "smart_auto" as const, label: "Smart Auto" },
              { value: "manual" as const, label: "Manual" },
            ]}
            value={adapterBindingMode}
            onChange={(mode) =>
              set({
                adapter_binding_mode: mode as "smart_auto" | "manual",
              })
            }
          />
        </Row>

        {manualAdapterBinding && (
          <div className="px-4 pb-3">
            <select
              value={settings.preferred_physical_adapter_guid || ""}
              onChange={(e) =>
                set({
                  preferred_physical_adapter_guid: e.target.value || null,
                })
              }
              disabled={networkAdaptersLoading}
              className="w-full rounded-[4px] px-3 py-2 text-[12.5px] outline-none transition-colors disabled:opacity-50"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                border: "1px solid var(--color-border-default)",
                color: "var(--color-text-primary)",
              }}
            >
              <option value="">Auto fallback (recommended)</option>
              {sortedAdapters.map((adapter) => {
                const label =
                  adapter.friendly_name || adapter.description || adapter.guid;
                const tags = [
                  adapter.kind && adapter.kind !== "other" ? adapter.kind : null,
                  adapter.is_up ? "up" : "down",
                  adapter.is_default_route ? "default" : null,
                ]
                  .filter(Boolean)
                  .join(" · ");
                return (
                  <option key={adapter.guid} value={adapter.guid}>
                    {tags ? `${label} (${tags})` : label}
                  </option>
                );
              })}
            </select>
            {adapterMissing && (
              <p className="mt-2 text-[11px] text-status-error">
                Selected adapter not found. Choose Auto or another adapter.
              </p>
            )}
          </div>
        )}

        {!manualAdapterBinding && (
          <div className="px-4 pb-3 text-[11px] text-text-muted">
            Current:{" "}
            <span className="font-mono text-text-primary">
              {vpnDiagnostics?.adapter_name || "Not resolved"}
            </span>
            <span className="text-text-dimmed"> · </span>
            <span className="text-text-primary">{routeSourceLabel}</span>
          </div>
        )}

        {networkAdaptersError && (
          <div className="px-4 pb-3 text-[11px] text-status-error">
            Failed to load adapters: {networkAdaptersError}
          </div>
        )}

        <Row
          label="API Tunneling"
          desc="Route game API calls through relay to bypass ISP blocking"
          tooltip={
            <Tooltip content="TCP traffic from game processes is also tunneled through the relay server. Helps when your ISP blocks game API endpoints.">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          }
        >
          <Toggle
            enabled={settings.enable_api_tunneling}
            onChange={(v) => set({ enable_api_tunneling: v })}
          />
        </Row>

        <details
          className="mx-4 mb-3 rounded-[5px]"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          <summary className="cursor-pointer px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-text-muted">
            Adapter diagnostics
          </summary>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 px-3 pb-3 text-[10.5px]">
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
          desc="Automatically check and install updates on startup"
        >
          <Toggle
            enabled={settings.update_settings.auto_check}
            onChange={(v) =>
              set({
                update_settings: { ...settings.update_settings, auto_check: v },
              })
            }
          />
        </Row>

        <div className="px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className="rounded-[3px] px-1.5 py-0.5 font-mono text-[11px] font-semibold"
                style={{
                  backgroundColor: "var(--color-bg-elevated)",
                  color: "var(--color-text-primary)",
                }}
              >
                v{__APP_VERSION__}
              </span>
              <UpdaterStatusLine
                status={updaterStatus}
                version={updaterVersion}
                error={updaterError}
              />
            </div>
            <div className="flex items-center gap-2">
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

          {updaterStatus === "update_available" && (
            <div className="mt-2 flex items-center gap-2 font-mono text-[11px] text-text-muted">
              <span>v{__APP_VERSION__}</span>
              <svg
                width="11"
                height="11"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
              <span
                style={{ color: "var(--color-accent-primary)" }}
                className="font-semibold"
              >
                v{updaterVersion}
              </span>
            </div>
          )}

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
        </div>

        <div
          className="border-t px-4 py-2.5 font-mono text-[10.5px] text-text-dimmed"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          Last checked:{" "}
          {updaterLastChecked
            ? new Date(updaterLastChecked * 1000).toLocaleString()
            : "Never"}
        </div>
      </Section>

      {/* Experimental */}
      {isTester && (
        <Section title="Experimental" tag="Tester">
          <Row
            label="Practice mode"
            desc="Add artificial latency for training"
          >
            <Toggle
              enabled={settings.experimental_mode}
              onChange={(v) => set({ experimental_mode: v })}
            />
          </Row>
          {settings.experimental_mode && (
            <div className="flex items-center justify-between px-4 pb-3">
              <span className="text-[11.5px] text-text-muted">
                Artificial latency
              </span>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[12px] font-semibold text-accent-secondary">
                  +{settings.artificial_latency_ms}ms
                </span>
                <div className="w-32">
                  <Slider
                    ariaLabel="Artificial latency"
                    min={0}
                    max={100}
                    step={5}
                    value={settings.artificial_latency_ms}
                    onChange={(v) => set({ artificial_latency_ms: v })}
                  />
                </div>
              </div>
            </div>
          )}
          <Row
            label="Custom relay server"
            desc="Override relay endpoint (host:port)"
          >
            <input
              type="text"
              value={settings.custom_relay_server}
              onChange={(e) => set({ custom_relay_server: e.target.value })}
              placeholder="auto"
              className="w-40 rounded-[4px] px-2 py-1.5 font-mono text-[12px] outline-none transition-colors"
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

      {/* Support */}
      <Section title="Support">
        <Row
          label="Network diagnostics"
          desc="Generate a support-ready bundle with ISP, routing, and split tunnel info"
        >
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void generateDiagnosticsBundle()}
            disabled={isGeneratingDiagnostics}
            loading={isGeneratingDiagnostics}
          >
            {isGeneratingDiagnostics ? "Generating" : "Generate"}
          </Button>
        </Row>
        {diagnosticsPath && (
          <div className="px-4 pb-3 text-[11px] text-text-muted">
            Saved to:{" "}
            <span className="break-all font-mono text-[10.5px] text-text-secondary">
              {diagnosticsPath}
            </span>
          </div>
        )}
        {diagnosticsError && (
          <div className="px-4 pb-3 text-[11px] text-status-error">
            {diagnosticsError}
          </div>
        )}
      </Section>

      {/* About */}
      <Section title="About">
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-[12.5px] text-text-secondary">
            SwiftTunnel Desktop{" "}
            <span className="font-mono text-text-dimmed">
              v{__APP_VERSION__}
            </span>
          </span>
          <div className="flex gap-3">
            <LinkButton onClick={() => systemOpenUrl("https://swifttunnel.net")}>
              Website
            </LinkButton>
            <LinkButton
              onClick={() => systemOpenUrl("https://discord.gg/swifttunnel")}
            >
              Discord
            </LinkButton>
          </div>
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-[13px] font-medium text-text-primary">
              Uninstall SwiftTunnel
            </div>
            <div className="text-[11px] text-text-muted">
              Remove app and revert all system changes
            </div>
          </div>
          <Button
            variant="destructive"
            size="sm"
            onClick={async () => {
              setIsUninstalling(true);
              setUninstallError(null);
              try {
                await systemUninstall();
              } catch (e) {
                setUninstallError(String(e));
                setIsUninstalling(false);
              }
            }}
            disabled={isUninstalling}
            loading={isUninstalling}
          >
            {isUninstalling ? "Uninstalling" : "Uninstall"}
          </Button>
        </div>
        {uninstallError && (
          <div className="px-4 pb-3 text-[11px] text-status-error">
            {uninstallError}
          </div>
        )}
      </Section>
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
      <div
        className="overflow-hidden rounded-[var(--radius-card)]"
        style={{
          backgroundColor: "var(--color-bg-card)",
          border: "1px solid var(--color-border-subtle)",
        }}
      >
        {children}
      </div>
    </section>
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
        className={`text-text-primary ${mono ? "font-mono text-[10px]" : "text-[11px]"}`}
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
      className="text-[11.5px] font-medium text-accent-secondary transition-opacity hover:opacity-80"
    >
      {children}
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
          ? `v${version} available`
          : status === "installing"
            ? `Installing v${version}…`
            : status === "error"
              ? error || "Update check failed"
              : "Not checked yet";

  return (
    <div className="flex items-center gap-1.5">
      {(status === "checking" || status === "installing") && (
        <svg className="h-3 w-3 animate-spin" viewBox="0 0 24 24" fill="none">
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
        >
          <path d="M20 6 9 17l-5-5" />
        </svg>
      )}
      {status === "update_available" && (
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 19V5M5 12l7-7 7 7" />
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
        >
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      )}
      <span className="text-[11.5px] font-medium" style={{ color }}>
        {text}
      </span>
    </div>
  );
}
