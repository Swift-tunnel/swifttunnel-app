import { useEffect, useState } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { useAuthStore } from "../../stores/authStore";
import { useUpdaterStore } from "../../stores/updaterStore";
import { vpnListNetworkAdapters } from "../../lib/commands";
import type { NetworkAdapterInfo } from "../../lib/types";
import { Chevron, Group, Row, Switch, Value } from "./ui";

declare const __APP_VERSION__: string;

function adapterName(adapter: NetworkAdapterInfo): string {
  return adapter.friendly_name || adapter.description || adapter.guid;
}

/** Adapters that can actually carry game traffic. */
function usable(adapter: NetworkAdapterInfo): boolean {
  return (
    adapter.is_up && adapter.kind !== "loopback" && adapter.kind !== "tunnel"
  );
}

/**
 * Lite's Settings screen.
 *
 * The full app's has five sections, a theme picker, a language picker, an
 * experimental block, a diagnostics dump and an uninstaller. What is left here
 * is the handful a Lite user can actually be expected to change, plus the
 * adapter override, which is the one setting that turns a machine that cannot
 * connect into one that can.
 */
export function LiteSettings() {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const email = useAuthStore((s) => s.email);
  const logout = useAuthStore((s) => s.logout);

  const status = useUpdaterStore((s) => s.status);
  const availableVersion = useUpdaterStore((s) => s.availableVersion);
  const checkForUpdates = useUpdaterStore((s) => s.checkForUpdates);
  const installUpdate = useUpdaterStore((s) => s.installUpdate);

  const [adapters, setAdapters] = useState<NetworkAdapterInfo[]>([]);
  const [pickingAdapter, setPickingAdapter] = useState(false);

  // Once when the screen opens, and again when the picker does in case a NIC
  // appeared in between. Not on a timer: the row below needs the list only to
  // put a name to a saved GUID.
  useEffect(() => {
    void vpnListNetworkAdapters()
      .then(setAdapters)
      .catch(() => setAdapters([]));
  }, [pickingAdapter]);

  function set(next: Parameters<typeof update>[0]) {
    update(next);
    void save();
  }

  const manualGuid =
    settings.adapter_binding_mode === "manual"
      ? settings.preferred_physical_adapter_guid
      : null;
  const manualAdapter = adapters.find((a) => a.guid === manualGuid);

  if (pickingAdapter) {
    return (
      <>
        <button
          type="button"
          onClick={() => setPickingAdapter(false)}
          className="mb-2 flex items-center gap-1.5 px-1 py-1 text-[11.5px] font-medium"
          style={{ color: "var(--color-text-muted)" }}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
          >
            <path d="m15 18-6-6 6-6" />
          </svg>
          Network adapter
        </button>
        <Group>
          <Row
            first
            label="Automatic"
            sub="Let SwiftTunnel pick the adapter carrying your traffic"
            onClick={() => {
              set({
                adapter_binding_mode: "smart_auto",
                preferred_physical_adapter_guid: null,
              });
              setPickingAdapter(false);
            }}
            right={
              settings.adapter_binding_mode === "smart_auto" ? (
                <Tick />
              ) : (
                <span style={{ width: 12 }} />
              )
            }
          />
          {adapters.filter(usable).map((adapter) => (
            <Row
              key={adapter.guid}
              label={adapterName(adapter)}
              sub={adapter.is_default_route ? "Default route" : adapter.kind}
              onClick={() => {
                set({
                  adapter_binding_mode: "manual",
                  preferred_physical_adapter_guid: adapter.guid,
                });
                setPickingAdapter(false);
              }}
              right={
                adapter.guid === manualGuid ? (
                  <Tick />
                ) : (
                  <span style={{ width: 12 }} />
                )
              }
            />
          ))}
        </Group>
      </>
    );
  }

  return (
    <>
      <Group title="Startup">
        <Row
          first
          label="Start with Windows"
          right={
            <Switch
              label="Start with Windows"
              checked={settings.run_on_startup}
              onChange={(next) => set({ run_on_startup: next })}
            />
          }
        />
        <Row
          label="Close to tray"
          sub="Keep the tunnel up when the window is closed"
          right={
            <Switch
              label="Close to tray"
              checked={settings.minimize_to_tray}
              onChange={(next) => set({ minimize_to_tray: next })}
            />
          }
        />
        <Row
          label="Reconnect automatically"
          sub="Retry after the connection drops"
          right={
            <Switch
              label="Reconnect automatically"
              checked={settings.auto_reconnect}
              onChange={(next) => set({ auto_reconnect: next })}
            />
          }
        />
      </Group>

      <Group title="Network">
        <Row
          first
          label="Adapter"
          sub="Which connection the tunnel binds to"
          onClick={() => setPickingAdapter(true)}
          right={
            <>
              <Value>
                {settings.adapter_binding_mode === "manual"
                  ? manualAdapter
                    ? adapterName(manualAdapter)
                    : "Manual"
                  : "Automatic"}
              </Value>
              <Chevron />
            </>
          }
        />
        <Row
          label="Idle while unfocused"
          sub="Stop polling once you alt-tab into the game"
          right={
            <Switch
              label="Idle while unfocused"
              checked={settings.idle_when_unfocused}
              onChange={(next) => set({ idle_when_unfocused: next })}
            />
          }
        />
      </Group>

      <Group title="About">
        <Row first label="Account" right={<Value>{email || "Signed out"}</Value>} />
        <Row
          label={
            availableVersion ? `Update to v${availableVersion}` : "Check for updates"
          }
          sub={`SwiftTunnel Lite v${__APP_VERSION__}`}
          disabled={status === "checking" || status === "installing"}
          onClick={() => {
            if (availableVersion) void installUpdate();
            else void checkForUpdates(true);
          }}
          right={
            <Value>
              {status === "checking"
                ? "Checking"
                : status === "installing"
                  ? "Installing"
                  : status === "up_to_date"
                    ? "Up to date"
                    : availableVersion
                      ? "Install"
                      : ""}
            </Value>
          }
        />
        <Row label="Sign out" tone="danger" onClick={() => void logout()} />
      </Group>
    </>
  );
}

function Tick() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-status-connected)"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
