import { type ReactNode, useEffect, useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useUpdaterStore } from "../../stores/updaterStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useToastStore } from "../../stores/toastStore";
import { Toggle } from "../common/Toggle";
import { Tooltip, InfoIcon } from "../common/Tooltip";
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
  const [isGeneratingDiagnostics, setIsGeneratingDiagnostics] = useState(false);
  const [diagnosticsPath, setDiagnosticsPath] = useState<string | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
  const [networkAdapters, setNetworkAdapters] = useState<
    NetworkAdapterInfo[] | null
  >(null);
  const [networkAdaptersLoading, setNetworkAdaptersLoading] = useState(false);
  const [networkAdaptersError, setNetworkAdaptersError] = useState<
    string | null
  >(null);
  const addToast = useToastStore((s) => s.addToast);
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
    if (vpnState !== "connected") {
      return;
    }
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
    const kindPriority = (kind: string) => {
      switch (kind) {
        case "ethernet": return 0;
        case "wifi": return 1;
        case "ppp": return 2;
        case "tunnel": return 3;
        case "loopback": return 4;
        default: return 5;
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

  const updaterDesc =
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
              : "Not checked yet";

  return (
    <div className="mx-auto flex max-w-[660px] flex-col gap-4">
      {/* ── Account ── */}
      <Section title="Account">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <div
              className="flex h-9 w-9 items-center justify-center rounded-full text-sm font-medium"
              style={{
                backgroundColor: "var(--color-accent-primary-soft-20)",
                color: "var(--color-accent-secondary)",
              }}
            >
              {email?.[0]?.toUpperCase() || "?"}
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
          <SegmentedPicker
            options={["Stable", "Live"] as UpdateChannel[]}
            value={settings.update_channel}
            onChange={(ch) => set({ update_channel: ch })}
          />
        </Row>
        <Row label="Auto Update" desc="Check and install updates on startup">
          <Toggle
            enabled={settings.update_settings.auto_check}
            onChange={(v) =>
              set({ update_settings: { ...settings.update_settings, auto_check: v } })
            }
          />
        </Row>
        <Row label="Run on Startup" desc="Launch SwiftTunnel when you sign into Windows">
          <Toggle
            enabled={settings.run_on_startup}
            onChange={(v) => set({ run_on_startup: v })}
          />
        </Row>
        <Row label="Auto Reconnect Tunnel" desc="Reconnect after restart if last session was connected">
          <Toggle
            enabled={settings.auto_reconnect}
            onChange={(v) => set({ auto_reconnect: v })}
          />
        </Row>
        <Row label="Discord Rich Presence" desc="Show tunnel status in Discord">
          <Toggle
            enabled={settings.enable_discord_rpc}
            onChange={(v) => set({ enable_discord_rpc: v })}
          />
        </Row>
      </Section>

      {/* ── Tunnel ── */}
      <Section title="Tunnel">
        <Row
          label="Adapter Selection"
          desc={
            manualAdapterBinding
              ? "Manual — locked to a specific adapter"
              : "Smart Auto — follows active route, rebinds on network change"
          }
          tooltip="Smart Auto detects your active network adapter from the OS routing table and rebinds automatically when you switch networks. Manual lets you pin a specific adapter."
        >
          <SegmentedPicker
            options={[
              { value: "smart_auto" as const, label: "Smart Auto" },
              { value: "manual" as const, label: "Manual" },
            ]}
            value={adapterBindingMode}
            onChange={(mode) => set({ adapter_binding_mode: mode })}
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
              className="w-full rounded-lg border bg-bg-elevated px-3 py-2 text-sm text-text-primary disabled:opacity-50"
              style={{ borderColor: "var(--color-border-default)" }}
              onFocus={(e) =>
                (e.currentTarget.style.borderColor = "var(--color-accent-primary)")
              }
              onBlur={(e) =>
                (e.currentTarget.style.borderColor = "var(--color-border-default)")
              }
            >
              <option value="">Auto fallback (Recommended)</option>
              {sortedAdapters.map((adapter) => {
                const label =
                  adapter.friendly_name || adapter.description || adapter.guid;
                const tags = [
                  adapter.kind && adapter.kind !== "other" ? adapter.kind : null,
                  adapter.is_up ? "up" : "down",
                  adapter.is_default_route ? "default" : null,
                ]
                  .filter(Boolean)
                  .join(", ");
                return (
                  <option key={adapter.guid} value={adapter.guid}>
                    {tags ? `${label} (${tags})` : label}
                  </option>
                );
              })}
            </select>
            {adapterMissing && (
              <p className="mt-2 text-xs text-status-error">
                Selected adapter not found. Choose Auto or another adapter.
              </p>
            )}
          </div>
        )}

        {!manualAdapterBinding && (
          <div className="px-4 pb-3 text-xs text-text-muted">
            Current:{" "}
            <span className="text-text-primary">
              {vpnDiagnostics?.adapter_name || "Not resolved"}
            </span>
            {" \u00B7 "}
            <span className="text-text-primary">{routeSourceLabel}</span>
          </div>
        )}

        {networkAdaptersError && (
          <div className="px-4 pb-3 text-xs text-status-error">
            Failed to load adapters: {networkAdaptersError}
          </div>
        )}

        <Row
          label="API Tunneling"
          desc="Route game API calls through relay to bypass ISP blocking"
          tooltip="When enabled, TCP traffic from game processes is also tunneled through the relay server. Helps if your ISP blocks game API endpoints. Requires TCP-capable relay."
        >
          <Toggle
            enabled={settings.enable_api_tunneling}
            onChange={(v) => set({ enable_api_tunneling: v })}
          />
        </Row>

        <details className="mx-4 mb-3 rounded-lg border border-border-subtle bg-bg-elevated">
          <summary className="cursor-pointer px-3 py-2 text-[11px] font-medium text-text-muted">
            Adapter Diagnostics
          </summary>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 px-3 pb-3 text-[11px]">
            <DiagItem label="State" value={vpnState} />
            <DiagItem label="Adapter" value={vpnDiagnostics?.adapter_name} />
            <DiagItem label="GUID" value={vpnDiagnostics?.adapter_guid} mono />
            <DiagItem label="Selected ifIndex" value={vpnDiagnostics?.selected_if_index} />
            <DiagItem label="Resolved ifIndex" value={vpnDiagnostics?.resolved_if_index} />
            <DiagItem label="Route source" value={routeSourceLabel} />
            <DiagItem label="Route target" value={vpnDiagnostics?.route_resolution_target_ip} />
            <DiagItem label="Has route" value={vpnDiagnostics?.has_default_route ? "yes" : "no"} />
            <DiagItem label="Manual binding" value={vpnDiagnostics?.manual_binding_active ? "yes" : "no"} />
            <DiagItem label="Cached override" value={vpnDiagnostics?.cached_override_used ? "yes" : "no"} />
            <DiagItem label="Binding stage" value={vpnDiagnostics?.binding_stage} />
            <DiagItem label="Validation" value={vpnDiagnostics?.last_validation_result} />
            <div className="col-span-2">
              <DiagItem label="Binding reason" value={vpnDiagnostics?.binding_reason} />
            </div>
            <DiagItem
              label="Packets"
              value={`${vpnDiagnostics?.packets_tunneled ?? 0} tunneled / ${vpnDiagnostics?.packets_bypassed ?? 0} bypassed`}
            />
          </div>
        </details>
      </Section>

      {/* ── Updates ── */}
      <Section title="Updates">
        <Row label="Status" desc={updaterDesc}>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void checkForUpdates(true)}
              disabled={updaterStatus === "checking" || updaterStatus === "installing"}
              className="rounded-[var(--radius-button)] border border-border-subtle px-3 py-1.5 text-xs text-text-primary transition-colors hover:bg-bg-hover disabled:opacity-50"
            >
              Check Now
            </button>
            {updaterStatus === "update_available" && (
              <button
                onClick={() => void installUpdate()}
                className="rounded-[var(--radius-button)] px-3 py-1.5 text-xs font-medium text-white"
                style={{ backgroundColor: "var(--color-accent-primary)" }}
              >
                Install
              </button>
            )}
          </div>
        </Row>
        <div className="px-4 pb-3 text-[11px] text-text-dimmed">
          Last checked:{" "}
          {updaterLastChecked
            ? new Date(updaterLastChecked * 1000).toLocaleString()
            : "Never"}
        </div>
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
            <div className="flex items-center justify-between px-4 pb-3">
              <span className="text-xs text-text-muted">
                Artificial Latency
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-accent-secondary">
                  +{settings.artificial_latency_ms}ms
                </span>
                <input
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
            </div>
          )}
          <Row label="Custom Relay Server" desc="Override relay endpoint (host:port)">
            <input
              type="text"
              value={settings.custom_relay_server}
              onChange={(e) => set({ custom_relay_server: e.target.value })}
              placeholder="auto"
              className="w-36 rounded-lg border bg-bg-elevated px-2 py-1.5 text-sm text-text-primary placeholder:text-text-dimmed focus:outline-none"
              style={{ borderColor: "var(--color-border-default)" }}
              onFocus={(e) =>
                (e.currentTarget.style.borderColor = "var(--color-accent-primary)")
              }
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "var(--color-border-default)";
                save();
              }}
            />
          </Row>
        </Section>
      )}

      {/* ── Support ── */}
      <Section title="Support">
        <Row
          label="Network Diagnostics"
          desc="Generate a support-ready bundle with ISP, routing, and split tunnel info"
        >
          <button
            onClick={() => void generateDiagnosticsBundle()}
            disabled={isGeneratingDiagnostics}
            className="rounded-[var(--radius-button)] border border-border-subtle px-3 py-1.5 text-xs text-text-primary transition-colors hover:bg-bg-hover disabled:opacity-50"
          >
            {isGeneratingDiagnostics ? "Generating..." : "Generate"}
          </button>
        </Row>
        {diagnosticsPath && (
          <div className="px-4 pb-3 text-xs text-text-muted">
            Saved to:{" "}
            <span className="break-all font-mono text-[11px] text-text-secondary">
              {diagnosticsPath}
            </span>
          </div>
        )}
        {diagnosticsError && (
          <div className="px-4 pb-3 text-xs text-status-error">
            {diagnosticsError}
          </div>
        )}
      </Section>

      {/* ── About ── */}
      <Section title="About">
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-sm text-text-secondary">
            SwiftTunnel Desktop v{__APP_VERSION__}
          </span>
          <div className="flex gap-3">
            <LinkButton onClick={() => systemOpenUrl("https://swifttunnel.net")}>
              Website
            </LinkButton>
            <LinkButton onClick={() => systemOpenUrl("https://discord.gg/swifttunnel")}>
              Discord
            </LinkButton>
          </div>
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <div>
            <div className="text-sm font-medium text-text-primary">
              Uninstall SwiftTunnel
            </div>
            <div className="text-xs text-text-muted">
              Remove app and revert all system changes
            </div>
          </div>
          <button
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
            className="rounded-[var(--radius-button)] px-3 py-1.5 text-xs font-medium text-white transition-opacity disabled:opacity-50"
            style={{ backgroundColor: "var(--color-status-error)" }}
            onMouseEnter={(e) => {
              if (!isUninstalling) e.currentTarget.style.opacity = "0.85";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.opacity = "1";
            }}
          >
            {isUninstalling ? "Uninstalling..." : "Uninstall"}
          </button>
        </div>
        {uninstallError && (
          <div className="px-4 pb-3 text-xs text-status-error">
            {uninstallError}
          </div>
        )}
      </Section>
    </div>
  );
}

// ── Sub-components ──

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-text-dimmed">
        {title}
      </div>
      <div className="overflow-hidden rounded-[var(--radius-card)] border border-border-subtle bg-bg-card">
        <div className="divide-y divide-border-subtle">{children}</div>
      </div>
    </section>
  );
}

function Row({
  label,
  desc,
  tooltip,
  children,
}: {
  label: string;
  desc: string;
  tooltip?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <div className="flex min-w-0 flex-col gap-0.5 pr-4">
        <span className="flex items-center gap-1.5 text-sm font-medium text-text-primary">
          {label}
          {tooltip && (
            <Tooltip content={tooltip}>
              <InfoIcon />
            </Tooltip>
          )}
        </span>
        <span className="text-xs text-text-muted">{desc}</span>
      </div>
      {children}
    </div>
  );
}

function SegmentedPicker<T extends string>({
  options,
  value,
  onChange,
}: {
  options: T[] | { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  const items = options.map((o) =>
    typeof o === "string" ? { value: o, label: o } : o,
  );
  return (
    <div className="flex gap-1">
      {items.map((item) => (
        <button
          key={item.value}
          onClick={() => onChange(item.value)}
          className="rounded px-3 py-1 text-xs transition-colors"
          style={{
            backgroundColor:
              value === item.value
                ? "var(--color-accent-primary)"
                : "var(--color-bg-hover)",
            color:
              value === item.value ? "white" : "var(--color-text-secondary)",
          }}
        >
          {item.label}
        </button>
      ))}
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
    <div className="flex flex-col">
      <span className="text-text-dimmed">{label}</span>
      <span
        className={`text-text-primary ${mono ? "font-mono" : ""}`}
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
      className="text-xs text-accent-secondary transition-opacity hover:opacity-80"
    >
      {children}
    </button>
  );
}
