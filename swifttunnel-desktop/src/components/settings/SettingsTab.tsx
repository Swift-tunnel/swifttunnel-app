import { type ReactNode, useEffect, useState } from "react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useUpdaterStore } from "../../stores/updaterStore";
import { useVpnStore } from "../../stores/vpnStore";
import { Toggle } from "../common/Toggle";
import {
  settingsGenerateNetworkDiagnosticsBundle,
  systemOpenUrl,
  vpnListNetworkAdapters,
} from "../../lib/commands";
import type { AppSettings, NetworkAdapterInfo, UpdateChannel } from "../../lib/types";

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
  const [networkAdapters, setNetworkAdapters] = useState<NetworkAdapterInfo[] | null>(
    null,
  );
  const [networkAdaptersLoading, setNetworkAdaptersLoading] = useState(false);
  const [networkAdaptersError, setNetworkAdaptersError] = useState<string | null>(
    null,
  );
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
        <Row label="Auto Update" desc="Check and install updates on app startup">
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
        <Row label="Run on Startup" desc="Launch SwiftTunnel when you sign into Windows">
          <Toggle
            enabled={settings.run_on_startup}
            onChange={(v) => set({ run_on_startup: v })}
          />
        </Row>
        <Row
          label="Auto Reconnect VPN"
          desc="Reconnect automatically after restart if your last session was connected"
        >
          <Toggle
            enabled={settings.auto_reconnect}
            onChange={(v) => set({ auto_reconnect: v })}
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

      {/* ── VPN ── */}
      <Section title="VPN">
        <Row
          label="Adapter Selection"
          desc="Smart Auto follows active route. Manual locks split tunnel to a specific adapter."
        >
          <div className="flex gap-1">
            <button
              onClick={() => set({ adapter_binding_mode: "smart_auto" })}
              className="rounded px-3 py-1 text-xs transition-colors"
              style={{
                backgroundColor:
                  adapterBindingMode === "smart_auto"
                    ? "var(--color-accent-primary)"
                    : "var(--color-bg-hover)",
                color:
                  adapterBindingMode === "smart_auto"
                    ? "white"
                    : "var(--color-text-secondary)",
              }}
            >
              Smart Auto
            </button>
            <button
              onClick={() => set({ adapter_binding_mode: "manual" })}
              className="rounded px-3 py-1 text-xs transition-colors"
              style={{
                backgroundColor:
                  adapterBindingMode === "manual"
                    ? "var(--color-accent-primary)"
                    : "var(--color-bg-hover)",
                color:
                  adapterBindingMode === "manual"
                    ? "white"
                    : "var(--color-text-secondary)",
              }}
            >
              Manual
            </button>
          </div>
        </Row>
        <Row
          label="Network Adapter"
          desc={
            manualAdapterBinding
              ? "Pick your active Wi‑Fi/Ethernet adapter (applies on next connect)."
              : "SwiftTunnel selects adapter from active route and rebinds automatically on network change."
          }
        >
          <select
            value={settings.preferred_physical_adapter_guid || ""}
            onChange={(e) =>
              set({
                preferred_physical_adapter_guid: e.target.value
                    ? e.target.value
                    : null,
              })
            }
            disabled={networkAdaptersLoading || !manualAdapterBinding}
            className="w-64 rounded border bg-bg-input px-2 py-1 text-sm text-text-primary disabled:opacity-50"
            style={{ borderColor: "var(--color-border-default)" }}
            onFocus={(e) =>
              (e.currentTarget.style.borderColor =
                "var(--color-accent-primary)")
            }
            onBlur={(e) =>
              (e.currentTarget.style.borderColor =
                "var(--color-border-default)")
            }
          >
            <option value="">
              {manualAdapterBinding ? "Auto fallback (Recommended)" : "Smart Auto"}
            </option>
            {(networkAdapters || [])
              .slice()
              .sort((a, b) => {
                if (a.is_default_route !== b.is_default_route) {
                  return a.is_default_route ? -1 : 1;
                }
                if (a.is_up !== b.is_up) {
                  return a.is_up ? -1 : 1;
                }
                const kindPriority = (kind: string) => {
                  switch (kind) {
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
              })
              .map((adapter) => {
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
        </Row>
        {!manualAdapterBinding && (
          <div className="px-4 pb-2 text-xs text-text-muted">
            Current adapter:{" "}
            <span className="text-text-primary">
              {vpnDiagnostics?.adapter_name || "Not resolved yet"}
            </span>
            {" · "}
            Source:{" "}
            <span className="text-text-primary">
              {routeSourceLabel}
              {vpnDiagnostics?.route_resolution_target_ip
                ? ` (${vpnDiagnostics.route_resolution_target_ip})`
                : ""}
            </span>
          </div>
        )}
        {networkAdaptersError && (
          <div className="px-4 pb-3 text-xs text-status-error">
            Failed to load adapters: {networkAdaptersError}
          </div>
        )}
        {!networkAdaptersError &&
          manualAdapterBinding &&
          settings.preferred_physical_adapter_guid &&
          networkAdapters &&
          !networkAdapters.some(
            (a) => a.guid === settings.preferred_physical_adapter_guid,
          ) && (
            <div className="px-4 pb-3 text-xs text-status-error">
              Selected adapter not found. Choose Auto (Recommended) or select
              another adapter.
            </div>
          )}
        <details className="mx-4 mb-3 rounded border border-border-subtle bg-bg-card p-3">
          <summary className="cursor-pointer text-xs font-medium text-text-secondary">
            Advanced Adapter Diagnostics
          </summary>
          <div className="mt-3 grid grid-cols-1 gap-1 text-[11px] text-text-muted">
            <span>
              State: <span className="text-text-primary">{vpnState}</span>
            </span>
            <span>
              Selected adapter:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.adapter_name || "unknown"}
              </span>
            </span>
            <span>
              Adapter GUID:{" "}
              <span className="font-mono text-text-primary">
                {vpnDiagnostics?.adapter_guid || "unknown"}
              </span>
            </span>
            <span>
              Selected ifIndex:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.selected_if_index ?? "n/a"}
              </span>
            </span>
            <span>
              Resolved ifIndex:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.resolved_if_index ?? "n/a"}
              </span>
            </span>
            <span>
              Route source:{" "}
              <span className="text-text-primary">{routeSourceLabel}</span>
            </span>
            <span>
              Route target:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.route_resolution_target_ip || "n/a"}
              </span>
            </span>
            <span>
              Has resolved route:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.has_default_route ? "yes" : "no"}
              </span>
            </span>
            <span>
              Manual binding active:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.manual_binding_active ? "yes" : "no"}
              </span>
            </span>
            <span>
              Packets tunneled / bypassed:{" "}
              <span className="text-text-primary">
                {vpnDiagnostics?.packets_tunneled ?? 0} /{" "}
                {vpnDiagnostics?.packets_bypassed ?? 0}
              </span>
            </span>
          </div>
        </details>
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

      {/* ── Support ── */}
      <Section title="Support">
        <Row
          label="Generate Network Diagnostics"
          desc="Create a support-ready .txt with ISP, routing, and split tunnel diagnostics"
        >
          <button
            onClick={() => void generateDiagnosticsBundle()}
            disabled={isGeneratingDiagnostics}
            className="rounded border border-border-subtle px-2.5 py-1 text-xs text-text-primary disabled:opacity-50"
          >
            {isGeneratingDiagnostics ? "Generating..." : "Generate Bundle"}
          </button>
        </Row>
        {diagnosticsPath && (
          <div className="px-4 pb-3 text-xs text-text-muted">
            Saved to:
            <div className="mt-1 break-all font-mono text-[11px] text-text-secondary">
              {diagnosticsPath}
            </div>
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
