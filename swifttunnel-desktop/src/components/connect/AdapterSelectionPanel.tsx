import { useEffect, useRef, useState } from "react";
import { vpnListNetworkAdapters } from "../../lib/commands";
import type { AppSettings, NetworkAdapterInfo } from "../../lib/types";
import { useSettingsStore } from "../../stores/settingsStore";
import { InfoIcon, Segmented, Tooltip } from "../ui";

function adapterDisplayName(adapter: NetworkAdapterInfo): string {
  return adapter.friendly_name || adapter.description || adapter.guid;
}

function isManualAdapterCandidate(adapter: NetworkAdapterInfo): boolean {
  return adapter.is_up && adapter.kind !== "loopback" && adapter.kind !== "tunnel";
}

function pickRecommendedManualAdapter(
  adapters: NetworkAdapterInfo[],
): NetworkAdapterInfo | null {
  return (
    adapters.find(
      (adapter) => adapter.is_default_route && isManualAdapterCandidate(adapter),
    ) ||
    adapters.find(
      (adapter) =>
        isManualAdapterCandidate(adapter) &&
        ["ethernet", "wifi", "ppp"].includes(adapter.kind),
    ) ||
    adapters.find(isManualAdapterCandidate) ||
    null
  );
}

function adapterStatusLabel(adapter: NetworkAdapterInfo): string {
  if (!adapter.is_up) return "[X] down";
  if (adapter.kind === "loopback" || adapter.kind === "tunnel") {
    return "[X] not usable";
  }
  return "[OK] usable";
}

function adapterNotUsableReason(adapter: NetworkAdapterInfo): string | null {
  if (!adapter.is_up) return "This adapter is down.";
  if (adapter.kind === "loopback") return "Loopback adapters cannot carry game traffic.";
  if (adapter.kind === "tunnel") {
    return "VPN/tunnel adapters cannot be used as the physical adapter.";
  }
  return null;
}

function adapterTags(adapter: NetworkAdapterInfo): string {
  return [
    adapter.kind && adapter.kind !== "other" ? adapter.kind : null,
    adapter.is_up ? "up" : "down",
    adapter.is_default_route ? "default" : null,
  ]
    .filter(Boolean)
    .join(" / ");
}

function sortAdapters(adapters: NetworkAdapterInfo[]): NetworkAdapterInfo[] {
  return adapters.slice().sort((a, b) => {
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
    return adapterDisplayName(a)
      .toLowerCase()
      .localeCompare(adapterDisplayName(b).toLowerCase());
  });
}

export function AdapterSelectionPanel({ disabled }: { disabled: boolean }) {
  const settings = useSettingsStore((s) => s.settings);
  const update = useSettingsStore((s) => s.update);
  const save = useSettingsStore((s) => s.save);

  const [networkAdapters, setNetworkAdapters] = useState<
    NetworkAdapterInfo[] | null
  >(null);
  const [networkAdaptersLoading, setNetworkAdaptersLoading] = useState(false);
  const [networkAdaptersError, setNetworkAdaptersError] = useState<string | null>(
    null,
  );
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function saveDebounced() {
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => {
      saveTimeoutRef.current = null;
      void save();
    }, 500);
  }

  function set(partial: Partial<AppSettings>) {
    update(partial);
    saveDebounced();
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

  const adapterBindingMode = settings.adapter_binding_mode;
  const manualAdapterBinding = adapterBindingMode === "manual";
  const sortedAdapters = sortAdapters(networkAdapters || []);
  const recommendedManualAdapter = pickRecommendedManualAdapter(sortedAdapters);
  const selectedManualAdapter = sortedAdapters.find(
    (adapter) => adapter.guid === settings.preferred_physical_adapter_guid,
  );
  const manualAdapterSelectValue =
    settings.preferred_physical_adapter_guid ||
    recommendedManualAdapter?.guid ||
    "";

  useEffect(() => {
    if (
      !manualAdapterBinding ||
      settings.preferred_physical_adapter_guid ||
      networkAdaptersLoading ||
      !recommendedManualAdapter
    ) {
      return;
    }

    set({
      preferred_physical_adapter_guid: recommendedManualAdapter.guid,
    });
  }, [
    manualAdapterBinding,
    settings.preferred_physical_adapter_guid,
    networkAdaptersLoading,
    recommendedManualAdapter?.guid,
  ]);

  const adapterMissing =
    !networkAdaptersError &&
    manualAdapterBinding &&
    settings.preferred_physical_adapter_guid &&
    networkAdapters &&
    !networkAdapters.some(
      (a) => a.guid === settings.preferred_physical_adapter_guid,
    );

  const desc = manualAdapterBinding
    ? selectedManualAdapter
      ? `Manual - ${adapterDisplayName(selectedManualAdapter)}`
      : "Manual - choose a specific adapter"
    : "Smart Auto - follows active route, rebinds on network change";
  const selectedAdapterNotUsableReason = selectedManualAdapter
    ? adapterNotUsableReason(selectedManualAdapter)
    : null;

  return (
    <section
      className="rounded-[var(--radius-card)] px-4 py-3 transition-colors"
      style={{
        backgroundColor: "var(--color-bg-card)",
        border: "1px solid var(--color-border-subtle)",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.025)",
      }}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3
              className="text-[12.5px] font-semibold text-text-primary"
              style={{ letterSpacing: "-0.005em" }}
            >
              Adapter selection
            </h3>
            <Tooltip content="Smart Auto follows the active Windows route. Manual pins one adapter when Windows chooses the wrong one.">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </div>
          <p className="mt-0.5 truncate text-[11px] leading-snug text-text-muted">
            {desc}
          </p>
        </div>
        <Segmented
          options={[
            { value: "smart_auto" as const, label: "Smart Auto" },
            { value: "manual" as const, label: "Manual" },
          ]}
          value={adapterBindingMode}
          disabled={disabled}
          onChange={(mode) => {
            const nextMode = mode as "smart_auto" | "manual";
            set({
              adapter_binding_mode: nextMode,
              preferred_physical_adapter_guid:
                nextMode === "manual" &&
                !settings.preferred_physical_adapter_guid &&
                recommendedManualAdapter
                  ? recommendedManualAdapter.guid
                  : settings.preferred_physical_adapter_guid,
            });
          }}
        />
      </div>

      {manualAdapterBinding && (
        <div className="mt-3">
          <select
            value={manualAdapterSelectValue}
            onChange={(e) =>
              set({
                preferred_physical_adapter_guid: e.target.value || null,
              })
            }
            disabled={disabled || networkAdaptersLoading}
            className="w-full rounded-[var(--radius-input)] px-3 py-2 text-[12.5px] outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            style={{
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-default)",
              color: "var(--color-text-primary)",
            }}
          >
            {manualAdapterSelectValue === "" && (
              <option value="" disabled>
                {networkAdaptersLoading
                  ? "Loading adapters..."
                  : "No usable adapter found"}
              </option>
            )}
            {sortedAdapters.map((adapter) => {
              const label = adapterDisplayName(adapter);
              const tags = adapterTags(adapter);
              const status = adapterStatusLabel(adapter);
              return (
                <option key={adapter.guid} value={adapter.guid}>
                  {tags ? `${status} - ${label} (${tags})` : `${status} - ${label}`}
                </option>
              );
            })}
          </select>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[10.5px] text-text-dimmed">
            <span>[OK] = usable for manual selection</span>
            <span>/</span>
            <span>[X] = down, loopback, or tunnel adapter</span>
          </div>
          {adapterMissing && (
            <p className="mt-2 text-[11px] text-status-error">
              Selected adapter not found. Choose Smart Auto or another adapter.
            </p>
          )}
          {selectedAdapterNotUsableReason && (
            <p className="mt-2 text-[11px] text-status-error">
              Adapter not usable. {selectedAdapterNotUsableReason}
            </p>
          )}
        </div>
      )}

      {networkAdaptersError && (
        <div className="mt-3 text-[11px] text-status-error">
          Failed to load adapters: {networkAdaptersError}
        </div>
      )}
    </section>
  );
}
