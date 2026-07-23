import { useEffect, useRef, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useAuthStore } from "../../stores/authStore";
import { useVpnStore } from "../../stores/vpnStore";
import { useServerStore } from "../../stores/serverStore";
import { useBoostStore } from "../../stores/boostStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useOptimizationStore } from "../../stores/optimizationStore";
import { useNetworkStore } from "../../stores/networkStore";
import { useToastStore } from "../../stores/toastStore";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import { reportError } from "../../lib/errors";
import { findRegionForVpnRegion } from "../../lib/regionMatch";
import { formatConnectedServerLabel } from "../../lib/connectedServer";
import { countryFlag, getLatencyColor } from "../../lib/utils";
import { getTotalTunneledMs, formatDuration } from "../../lib/tunnelTime";
import {
  OPTIMIZATIONS,
  type OptimizationDef,
} from "../optimization/optimizationCatalog";
import type { Config, RobloxSettingsConfig } from "../../lib/types";
import { Button, Spinner, Toggle } from "../ui";
import { FpsSlider } from "../boost/FpsSlider";
import { SwiftLogo } from "../common/SwiftLogo";
import {
  PresetsPanel,
  PresetsDialog,
  type PresetMode,
} from "./PresetsCard";
import { usePresetStore } from "../../stores/presetStore";

const ROBLOX_ART =
  "https://images.rbxcdn.com/5348266ea6c5e67b19d6a814cbbb70f6.jpg";

const TRANSITIONING = new Set([
  "fetching_config",
  "configuring_split_tunnel",
  "connecting",
  "disconnecting",
]);

// The intro animation should play once per app launch, not on every tab switch.
let homeIntroPlayed = false;

// ── Recommended optimizations for the Optimize checklist (safe, high impact) ──
const CATALOG_INDEX = new Map<string, OptimizationDef>(
  OPTIMIZATIONS.map((o): [string, OptimizationDef] => [o.id, o]),
);
const RECOMMENDED_IDS = [
  "game_mode_enable",
  "mouse_acceleration_disable",
  "visual_effects_performance",
  "game_bar_dvr_disable",
  "background_apps_disable",
  "menu_show_delay_fast",
];
const RECOMMENDED: OptimizationDef[] = RECOMMENDED_IDS.map((id) =>
  CATALOG_INDEX.get(id),
).filter((d): d is OptimizationDef => Boolean(d));

// ── Getting-started checklist: locally skippable steps ──
const SKIP_KEY = "st.checklistSkipped";
function loadSkipped(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(SKIP_KEY) || "[]");
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
function saveSkipped(ids: string[]) {
  try {
    localStorage.setItem(SKIP_KEY, JSON.stringify(ids));
  } catch {
    /* best-effort */
  }
}

// Once every setup step is done, the checklist is retired for good — keyed by
// account so it stays gone across app updates but returns fresh for a new login.
const DONE_KEY = "st.checklistDone";
function isChecklistDone(email: string | null): boolean {
  if (!email) return false;
  try {
    const map = JSON.parse(localStorage.getItem(DONE_KEY) || "{}");
    return Boolean(map && map[email]);
  } catch {
    return false;
  }
}
function markChecklistDone(email: string | null) {
  if (!email) return;
  try {
    const map = JSON.parse(localStorage.getItem(DONE_KEY) || "{}") || {};
    map[email] = true;
    localStorage.setItem(DONE_KEY, JSON.stringify(map));
  } catch {
    /* best-effort */
  }
}

export function HomeTab() {
  const [intro] = useState(() => {
    const first = !homeIntroPlayed;
    homeIntroPlayed = true;
    return first;
  });

  const email = useAuthStore((s) => s.email);
  const rawName = email ? email.split("@")[0] : "player";
  const name = rawName.charAt(0).toUpperCase() + rawName.slice(1);

  const vpnState = useVpnStore((s) => s.state);
  const vpnRegionId = useVpnStore((s) => s.region);
  const serverEndpoint = useVpnStore((s) => s.serverEndpoint);
  const ping = useVpnStore((s) => s.ping);
  const connect = useVpnStore((s) => s.connect);
  const disconnect = useVpnStore((s) => s.disconnect);
  const regions = useServerStore((s) => s.regions);
  const servers = useServerStore((s) => s.servers);

  const settings = useSettingsStore((s) => s.settings);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const setTab = useSettingsStore((s) => s.setTab);
  const navigateTo = useDeepLinkStore((s) => s.navigateTo);

  const robloxRunning = useBoostStore((s) => s.robloxRunning);
  const fetchMetrics = useBoostStore((s) => s.fetchMetrics);
  const boostUpdate = useBoostStore((s) => s.updateConfig);
  const restartRoblox = useBoostStore((s) => s.restartRoblox);

  const optStatus = useOptimizationStore((s) => s.status);
  const loadActive = useOptimizationStore((s) => s.loadActive);
  const presetCount = usePresetStore((s) => s.presets.length);

  const [presetMode, setPresetMode] = useState<PresetMode>(null);
  const [skipped, setSkipped] = useState<string[]>(loadSkipped);
  const [checklistDone, setChecklistDone] = useState(() =>
    isChecklistDone(email),
  );
  const [showSplash, setShowSplash] = useState(intro);

  useEffect(() => {
    void fetchMetrics();
    const id = window.setInterval(() => void fetchMetrics(), 4000);
    return () => window.clearInterval(id);
  }, [fetchMetrics]);

  useEffect(() => {
    void loadActive();
  }, [loadActive]);

  // First launch shows the welcome for a beat before the dashboard loads in.
  useEffect(() => {
    if (!showSplash) return;
    const t = window.setTimeout(() => setShowSplash(false), 2600);
    return () => window.clearTimeout(t);
  }, [showSplash]);

  const isConnected = vpnState === "connected";
  const isBusy = TRANSITIONING.has(vpnState);
  const currentRegion = findRegionForVpnRegion(regions, vpnRegionId);
  const connectedServerLabel = formatConnectedServerLabel(
    serverEndpoint,
    servers,
    vpnRegionId,
  );
  const prevRegion =
    findRegionForVpnRegion(regions, settings.selected_region) ??
    regions.find((r) => r.id === settings.selected_region);

  const rs = settings.config.roblox_settings;

  const activeCount = Object.values(optStatus).filter(
    (v) => v === "active",
  ).length;
  const gamesCount = settings.selected_game_presets.length;
  const totalMs = getTotalTunneledMs();

  // ── Roblox controls use a draft + explicit Apply (like the Optimize page),
  // so a "Restart & Apply" prompt shows before anything hits your live game.
  // Failures surface as a toast — otherwise a failed Apply (e.g. Roblox not
  // installed yet) looks like the button silently did nothing. ──
  async function applyRobloxDraft(draft: RobloxSettingsConfig) {
    try {
      const cur = useSettingsStore.getState().settings;
      const nextConfig: Config = { ...cur.config, roblox_settings: draft };
      const applied = await boostUpdate(JSON.stringify(nextConfig));
      updateSettings({ config: applied });
      await saveSettings();
      useToastStore.getState().addToast({
        type: "success",
        message: "Roblox settings applied",
      });
    } catch (e) {
      // Plain language for the user, real detail to the log — a raw Rust error
      // string in a toast on the home screen helps nobody.
      reportError("Apply Roblox settings", e);
      useToastStore.getState().addToast({
        type: "error",
        message: "Couldn't apply Roblox settings. Try the Repair tab if this keeps happening.",
      });
      throw e;
    }
  }
  async function restartApplyRobloxDraft(draft: RobloxSettingsConfig) {
    await applyRobloxDraft(draft);
    try {
      await restartRoblox();
    } catch (e) {
      reportError("Restart Roblox", e);
      useToastStore.getState().addToast({
        type: "error",
        message: "Settings applied, but Roblox couldn't restart — close and reopen it.",
      });
      throw e;
    }
  }

  function toggleConnection(next: boolean) {
    if (isBusy) return;
    if (next) {
      if (prevRegion) void connect(prevRegion.id, settings.selected_game_presets);
    } else {
      void disconnect();
    }
  }

  function skip(id: string) {
    setSkipped((prev) => {
      if (prev.includes(id)) return prev;
      const next = [...prev, id];
      saveSkipped(next);
      return next;
    });
  }

  const overlayOn = settings.config.overlay.enabled;
  const statusText = isConnected
    ? (currentRegion?.name ?? "Connected")
    : isBusy
      ? "Connecting…"
      : vpnState === "error"
        ? "Connection error"
        : "Not connected";

  const setupItems: SetupItem[] = [
    {
      id: "tunnel",
      title: "Connect a tunnel",
      desc: "Route your game traffic through a SwiftTunnel relay.",
      done: totalMs > 0 || isConnected || skipped.includes("tunnel"),
      action: () => setTab("connect"),
    },
    {
      id: "optimize",
      title: "Apply an optimization",
      desc: "Turn on a tweak to gain FPS or lower latency.",
      done: activeCount > 0 || skipped.includes("optimize"),
      action: () => setTab("optimization"),
    },
    {
      id: "overlay",
      title: "Set up your overlay",
      desc: "Show FPS, ping and more on top of your game.",
      done: overlayOn || skipped.includes("overlay"),
      action: () => setTab("ingame"),
    },
    {
      id: "preset",
      title: "Create a preset",
      desc: "Save your setup and share it with friends.",
      done: presetCount > 0 || skipped.includes("preset"),
      action: () => setPresetMode("create"),
    },
  ];

  // Retire the checklist permanently the moment every step is satisfied.
  const allSetupDone = setupItems.every((i) => i.done);
  useEffect(() => {
    if (allSetupDone && email && !checklistDone) {
      markChecklistDone(email);
      setChecklistDone(true);
    }
  }, [allSetupDone, email, checklistDone]);

  if (showSplash) {
    return <WelcomeSplash name={name} />;
  }

  return (
    <div className="relative flex w-full flex-col gap-4 pb-6">
      {/* ── Header ── */}
      <div className="pb-0.5">
        <motion.h1
          initial={intro ? { opacity: 0, y: 8 } : false}
          animate={intro ? { opacity: 1, y: 0 } : undefined}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="text-[27px] font-semibold leading-tight"
          style={{
            letterSpacing: "-0.03em",
            backgroundImage:
              "linear-gradient(120deg, #ffffff 0%, #ffffff 38%, #9a9aa3 100%)",
            WebkitBackgroundClip: "text",
            backgroundClip: "text",
            WebkitTextFillColor: "transparent",
            color: "transparent",
          }}
        >
          Welcome back, <span data-no-translate="">{name}</span>
        </motion.h1>
        <p className="mt-1 text-[12.5px] text-text-muted">
          Here&apos;s your SwiftTunnel at a glance.
        </p>
      </div>

      <HomeCommandCenter
        animate={intro}
        delay={0.1}
        // Disconnected shows the saved region's flag, not a stray satellite —
        // it previews what "Reconnect to <region>" will actually do. The tile's
        // border already carries the live/idle distinction.
        flag={
          isConnected && currentRegion
            ? countryFlag(currentRegion.country_code)
            : prevRegion
              ? countryFlag(prevRegion.country_code)
              : "🌐"
        }
        name={name}
        regionName={
          isConnected
            ? connectedServerLabel
            : (prevRegion?.name ?? "Choose a region")
        }
        statusText={statusText}
        relayRtt={isConnected ? ping : null}
        live={isConnected}
        activeCount={activeCount}
        robloxRunning={robloxRunning}
        toggleDisabled={isBusy || (!isConnected && !prevRegion)}
        onToggle={toggleConnection}
        hint={
          isConnected
            ? "Tunnel active"
            : prevRegion
              ? `Reconnect to ${prevRegion.name}`
              : "No saved region yet"
        }
      />

      {/* ── Roblox (full width) ──
          Configure deep-links straight into Roblox's optimize page; it used to
          land on the games list, so you had to click Roblox again. */}
      <RobloxCard
        animate={intro}
        delay={0.16}
        running={robloxRunning}
        savedRs={rs}
        onApply={applyRobloxDraft}
        onRestartApply={restartApplyRobloxDraft}
        onConfigure={() => navigateTo({ tab: "games", game: "roblox" })}
      />

      {/* ── Two columns: content (left) · checklist + shortcuts (right) ── */}
      <div className="grid gap-3 lg:grid-cols-12 lg:items-start">
        {/* LEFT */}
        <div className="flex flex-col gap-3 lg:col-span-7">
          {/* One recessed strip, not three floating cards — these are three
              readings off the same machine, so they share a surface. */}
          <div className="grid grid-cols-3 divide-x divide-[color:var(--color-border-subtle)] overflow-hidden rounded-[var(--radius-card)] surface-card">
            <StatBox
              animate={intro}
              delay={0.14}
              value={String(activeCount)}
              label="Optimizations active"
              cta="View optimizations"
              onClick={() => setTab("optimization")}
              icon={
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent-primary)" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M13 2L3 14h7l-1 8 10-12h-7z" />
                </svg>
              }
            />
            <StatBox
              animate={intro}
              delay={0.17}
              value={String(gamesCount)}
              label="Games optimized"
              cta="View games"
              onClick={() => setTab("games")}
              icon={
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent-primary)" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M6 12h4M8 10v4M15 11h.01M18 13h.01" />
                  <rect x="2" y="6" width="20" height="12" rx="4" />
                </svg>
              }
            />
            <StatBox
              animate={intro}
              delay={0.2}
              value={formatDuration(totalMs)}
              label="Time tunneled"
              cta="Open tunnel"
              onClick={() => setTab("connect")}
              icon={
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-accent-primary)" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="9" />
                  <path d="M12 7v5l3 2" />
                </svg>
              }
            />
          </div>

          <PresetsPanel
            animate={intro}
            delay={0.24}
            onCreate={() => setPresetMode("create")}
            onImport={() => setPresetMode("import")}
          />

          <NetworkStatusCard
            animate={intro}
            delay={0.28}
            onConfigure={() => setTab("network")}
          />

          <ShortcutRow animate={intro} delay={0.32} setTab={setTab} />
        </div>

        {/* RIGHT */}
        <div className="flex flex-col gap-3 lg:col-span-5">
          {!checklistDone && (
            <SetupChecklistCard
              animate={intro}
              delay={0.16}
              items={setupItems}
              onSkip={skip}
              onSkipAll={() =>
                setupItems.filter((i) => !i.done).forEach((i) => skip(i.id))
              }
            />
          )}

          <OptimizeChecklistCard
            animate={intro}
            delay={0.22}
            optStatus={optStatus}
            onSeeAll={() => setTab("optimization")}
          />
        </div>
      </div>

      <PresetsDialog mode={presetMode} onClose={() => setPresetMode(null)} />
    </div>
  );
}

// ── First-launch welcome (shows for ~5s, then the dashboard loads in) ──

function WelcomeSplash({ name }: { name: string }) {
  return (
    <div className="flex min-h-[72vh] w-full flex-col items-center justify-center gap-6 text-center">
      <motion.div
        initial={{ opacity: 0, scale: 0.86, y: 6 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
      >
        <SwiftLogo size={112} />
      </motion.div>
      <h1
        className="flex flex-wrap items-baseline justify-center gap-x-3 text-[36px] font-semibold leading-tight"
        style={{ letterSpacing: "-0.03em" }}
      >
        <SplashWord delay={0.45}>Welcome</SplashWord>
        <SplashWord delay={0.61}>back,</SplashWord>
        <SplashWord delay={0.77} noTranslate>
          {name}
        </SplashWord>
      </h1>
    </div>
  );
}

// One word of the welcome, revealed on a stagger so the line "types itself in".
function SplashWord({
  children,
  delay,
  noTranslate,
}: {
  children: string;
  delay: number;
  noTranslate?: boolean;
}) {
  return (
    <motion.span
      data-no-translate={noTranslate ? "" : undefined}
      initial={{ opacity: 0, y: 14, filter: "blur(7px)" }}
      animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      transition={{ delay, duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      style={{
        backgroundImage:
          "linear-gradient(180deg, #ffffff 0%, #ffffff 45%, #9a9aa3 100%)",
        WebkitBackgroundClip: "text",
        backgroundClip: "text",
        WebkitTextFillColor: "transparent",
        color: "transparent",
      }}
    >
      {children}
    </motion.span>
  );
}

function Card({
  children,
  delay = 0,
  className,
  animate,
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
  animate: boolean;
}) {
  return (
    <motion.section
      initial={animate ? { opacity: 0, y: 12 } : false}
      animate={animate ? { opacity: 1, y: 0 } : undefined}
      transition={{ delay, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className={`rounded-[var(--radius-card)] surface-card p-3.5 ${className ?? ""}`}
    >
      {children}
    </motion.section>
  );
}

// ── Tunnel bar ──

function HomeCommandCenter({
  name,
  flag,
  regionName,
  statusText,
  relayRtt,
  live,
  activeCount,
  robloxRunning,
  hint,
  toggleDisabled,
  onToggle,
  animate,
  delay,
}: {
  name: string;
  flag: string;
  regionName: string;
  statusText: string;
  relayRtt: number | null;
  live: boolean;
  activeCount: number;
  robloxRunning: boolean;
  hint: string;
  toggleDisabled: boolean;
  onToggle: (v: boolean) => void;
  animate: boolean;
  delay: number;
}) {
  return (
    <motion.section
      initial={animate ? { opacity: 0, y: 12 } : false}
      animate={animate ? { opacity: 1, y: 0 } : undefined}
      transition={{ delay, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className="corner-frame relative z-[1] overflow-hidden rounded-[var(--radius-card)] border border-[color:var(--color-border-subtle)] surface-card"
    >
      <div aria-hidden="true" className="dot-grid pointer-events-none absolute inset-0 opacity-55" />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(circle at 18% 12%, var(--color-accent-primary-soft-12), transparent 32%)",
        }}
      />

      <div className="relative flex items-start justify-between gap-5 border-b border-[color:var(--color-border-subtle)] px-5 py-4">
        <div className="min-w-0">
          <div className="eyebrow">SwiftTunnel control</div>
          <div className="mt-1 truncate text-[20px] font-semibold leading-tight text-text-primary">
            <span data-no-translate="">{name}</span>&apos;s session
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-[12px] text-text-muted">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{
                backgroundColor: live
                  ? "var(--color-accent-primary)"
                  : "var(--color-text-dimmed)",
                boxShadow: live
                  ? "0 0 9px var(--color-accent-primary)"
                  : "none",
              }}
            />
            <span>{statusText}</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Toggle
            enabled={live}
            disabled={toggleDisabled}
            ariaLabel="Reconnect to your last tunnel"
            onChange={onToggle}
          />
          <span className="text-[10px] text-text-dimmed">{hint}</span>
        </div>
      </div>

      {/* Deliberately NOT the Connect route path — Home gets a boost gauge and
          a subsystem status stack, so the two tabs don't show the same diagram. */}
      <div className="relative flex flex-wrap items-center gap-x-6 gap-y-5 px-5 py-5">
        <BoostGauge active={activeCount} total={OPTIMIZATIONS.length} live={live} />

        <div className="flex min-w-[210px] flex-1 flex-col gap-2">
          <StatusRow
            label="Tunnel"
            value={live ? "Connected" : "Offline"}
            detail={`${flag} ${regionName}`}
            tone={
              live
                ? "var(--color-status-connected)"
                : "var(--color-text-dimmed)"
            }
            on={live}
          />
          <StatusRow
            label="Relay ping"
            value={relayRtt !== null ? `${relayRtt} ms` : "—"}
            detail={live ? "measured, live" : "measured on connect"}
            tone={
              relayRtt !== null
                ? getLatencyColor(relayRtt)
                : "var(--color-text-dimmed)"
            }
            on={relayRtt !== null}
          />
          <StatusRow
            label="Roblox"
            value={robloxRunning ? "Running" : "Idle"}
            detail={robloxRunning ? "game detected" : "waiting for game"}
            tone={
              robloxRunning
                ? "var(--color-accent-primary)"
                : "var(--color-text-dimmed)"
            }
            on={robloxRunning}
          />
        </div>
      </div>
    </motion.section>
  );
}

/** Speedometer arc showing how much of the optimization catalog is active.
 *  A radial gauge, deliberately unlike Connect's horizontal route path. */
function BoostGauge({
  active,
  total,
  live,
}: {
  active: number;
  total: number;
  live: boolean;
}) {
  const pct = total > 0 ? Math.min(1, active / total) : 0;
  const W = 172;
  const stroke = 11;
  const cx = W / 2;
  const cy = 92;
  const r = 74;
  // Top semicircle, left → right.
  const arc = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
  const len = Math.PI * r;
  const tone =
    active > 0 ? "var(--color-status-connected)" : "var(--color-text-dimmed)";

  return (
    <div className="relative shrink-0" style={{ width: W, height: 104 }}>
      <svg width={W} height={104} viewBox={`0 0 ${W} 104`} className="block">
        <path
          d={arc}
          fill="none"
          stroke="var(--color-bg-base)"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        <path
          d={arc}
          fill="none"
          stroke={tone}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${pct * len} ${len}`}
          style={{
            transition: "stroke-dasharray 600ms cubic-bezier(0.16,1,0.3,1)",
            filter:
              active > 0
                ? "drop-shadow(0 0 6px var(--color-status-connected-soft-20))"
                : "none",
          }}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-1 flex flex-col items-center">
        <span className="readout readout-lg" style={{ color: tone }}>
          {active}
        </span>
        <span className="eyebrow mt-1">
          of {total} · {live ? "tunnel on" : "boosts"}
        </span>
      </div>
    </div>
  );
}

/** One subsystem's state in Home's status stack. */
function StatusRow({
  label,
  value,
  detail,
  tone,
  on,
}: {
  label: string;
  value: string;
  detail: string;
  tone: string;
  on: boolean;
}) {
  return (
    <div
      className="flex items-center gap-3 rounded-[10px] px-3 py-2"
      style={{
        backgroundColor: "var(--color-bg-base)",
        border: "1px solid var(--color-border-subtle)",
      }}
    >
      <span
        className="h-2 w-2 shrink-0 rounded-full"
        style={{
          backgroundColor: tone,
          boxShadow: on ? `0 0 8px ${tone}` : "none",
        }}
      />
      <span className="min-w-0 flex-1">
        <span className="block text-[9px] font-semibold uppercase tracking-[0.1em] text-text-dimmed">
          {label}
        </span>
        <span className="block truncate text-[10px] text-text-muted">
          {detail}
        </span>
      </span>
      <span
        className="shrink-0 text-[12.5px] font-semibold"
        style={{ color: tone }}
      >
        {value}
      </span>
    </div>
  );
}

// ── Stat tile (Hone-style: icon, number, label, action) ──

function StatBox({
  icon,
  value,
  label,
  cta,
  onClick,
  animate,
  delay,
}: {
  icon: ReactNode;
  value: string;
  label: string;
  cta: string;
  onClick: () => void;
  animate: boolean;
  delay: number;
}) {
  return (
    <motion.div
      initial={animate ? { opacity: 0, y: 10 } : false}
      animate={animate ? { opacity: 1, y: 0 } : undefined}
      transition={{ delay, duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col p-3"
    >
      <div className="flex items-start justify-between">
        <span className="icon-orb flex h-8 w-8 items-center justify-center">
          {icon}
        </span>
        <span
          className="flex h-4 w-4 items-center justify-center rounded-full text-text-dimmed"
          style={{ border: "1px solid var(--color-border-subtle)" }}
        >
          <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 6l6 6-6 6" />
          </svg>
        </span>
      </div>
      <div className="readout readout-lg mt-3 truncate">{value}</div>
      <div className="eyebrow mt-1.5">{label}</div>
      <button
        type="button"
        onClick={onClick}
        className="mt-2.5 w-full rounded-[7px] py-1.5 text-[10.5px] font-medium text-text-secondary transition-colors hover:text-text-primary"
        style={{ backgroundColor: "var(--color-bg-base)" }}
      >
        {cta}
      </button>
    </motion.div>
  );
}

// ── Getting-started checklist ──

interface SetupItem {
  id: string;
  title: string;
  desc: string;
  done: boolean;
  action: () => void;
}

function SetupChecklistCard({
  items,
  onSkip,
  onSkipAll,
  animate,
  delay,
}: {
  items: SetupItem[];
  onSkip: (id: string) => void;
  onSkipAll: () => void;
  animate: boolean;
  delay: number;
}) {
  const done = items.filter((i) => i.done).length;
  const allDone = done === items.length;
  return (
    <Card animate={animate} delay={delay}>
      <div className="flex items-center gap-2.5">
        <ProgressRing value={done} total={items.length} />
        <div>
          <div className="text-[13px] font-semibold text-text-primary">
            Getting started
          </div>
          <div className="text-[10.5px] text-text-muted">
            {done} of {items.length} completed
          </div>
        </div>
      </div>

      <div className="mt-1.5 flex flex-col divide-y divide-[color:var(--color-border-subtle)]">
        {items.map((item) => (
          <div key={item.id} className="flex items-center gap-2.5 py-2.5">
            <CheckCircle done={item.done} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={item.action}
                  className={`text-[12.5px] font-semibold ${item.done ? "text-text-muted" : "text-text-primary"}`}
                >
                  {item.title}
                </button>
                {!item.done && (
                  <button
                    type="button"
                    onClick={() => onSkip(item.id)}
                    className="text-[10.5px] text-text-dimmed transition-colors hover:text-text-secondary"
                  >
                    Skip ›
                  </button>
                )}
              </div>
              <div className="truncate text-[10.5px] leading-snug text-text-muted">
                {item.desc}
              </div>
            </div>
            <button
              type="button"
              onClick={item.action}
              aria-label={`Open ${item.title}`}
              className="shrink-0 text-text-dimmed transition-colors hover:text-text-primary"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 6l6 6-6 6" />
              </svg>
            </button>
          </div>
        ))}
      </div>

      {!allDone && (
        <button
          type="button"
          onClick={onSkipAll}
          className="mt-2.5 rounded-[7px] px-2.5 py-1 text-[10.5px] font-medium text-text-secondary transition-colors hover:text-text-primary"
          style={{ backgroundColor: "var(--color-bg-base)" }}
        >
          Mark all as complete
        </button>
      )}
    </Card>
  );
}

// ── Recommended-optimizations checklist ──

function OptimizeChecklistCard({
  optStatus,
  onSeeAll,
  animate,
  delay,
}: {
  optStatus: Record<string, string>;
  onSeeAll: () => void;
  animate: boolean;
  delay: number;
}) {
  const activate = useOptimizationStore((s) => s.activate);
  const deactivate = useOptimizationStore((s) => s.deactivate);

  const doneCount = RECOMMENDED.filter(
    (d) => optStatus[d.id] === "active",
  ).length;
  const pct = RECOMMENDED.length ? doneCount / RECOMMENDED.length : 0;

  function toggle(def: OptimizationDef) {
    if (optStatus[def.id] === "active") void deactivate(def);
    else void activate(def);
  }

  return (
    <Card animate={animate} delay={delay}>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[12.5px] font-semibold text-text-primary">
            Recommended
          </div>
          <div className="truncate text-[10.5px] text-text-muted">
            High-impact, safe tweaks — flip one on to apply it.
          </div>
        </div>
        <span className="shrink-0 text-[11.5px] font-semibold text-text-secondary">
          {doneCount}/{RECOMMENDED.length}
        </span>
      </div>

      <div
        className="mt-2 h-1 w-full overflow-hidden rounded-full"
        style={{ backgroundColor: "var(--color-bg-base)" }}
      >
        <motion.div
          className="h-full rounded-full"
          style={{ backgroundColor: "var(--color-accent-primary)" }}
          initial={false}
          animate={{ width: `${pct * 100}%` }}
          transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        />
      </div>

      <div className="mt-1 flex flex-col divide-y divide-[color:var(--color-border-subtle)]">
        {RECOMMENDED.map((def) => {
          const st = optStatus[def.id];
          const busy = st === "activating" || st === "deactivating";
          return (
            <div key={def.id} className="flex items-center gap-2.5 py-2">
              <CheckCircle done={st === "active"} />
              <span className="min-w-0 flex-1 truncate text-[12px] font-medium text-text-primary">
                {def.name}
              </span>
              {busy ? (
                <Spinner size={14} color="var(--color-text-muted)" />
              ) : (
                <Toggle
                  enabled={st === "active"}
                  ariaLabel={def.name}
                  onChange={() => toggle(def)}
                />
              )}
            </div>
          );
        })}
      </div>

      <button
        type="button"
        onClick={onSeeAll}
        className="mt-2 flex items-center gap-1 text-[11px] font-medium text-text-secondary transition-colors hover:text-text-primary"
      >
        See all optimizations
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 12h14M13 6l6 6-6 6" />
        </svg>
      </button>
    </Card>
  );
}

// ── Roblox quick-controls card ──

function RobloxCard({
  running,
  savedRs,
  onApply,
  onRestartApply,
  onConfigure,
  animate,
  delay,
}: {
  running: boolean;
  savedRs: RobloxSettingsConfig;
  onApply: (draft: RobloxSettingsConfig) => Promise<void>;
  onRestartApply: (draft: RobloxSettingsConfig) => Promise<void>;
  onConfigure: () => void;
  animate: boolean;
  delay: number;
}) {
  const [draft, setDraft] = useState<RobloxSettingsConfig>(savedRs);
  const [busy, setBusy] = useState<null | "apply" | "restart">(null);

  // Adopt external changes to the saved settings (e.g. a preset was applied)
  // only when the user has no pending edits of their own.
  const syncedRef = useRef(savedRs);
  useEffect(() => {
    if (savedRs === syncedRef.current) return;
    const hadEdits =
      JSON.stringify(draft) !== JSON.stringify(syncedRef.current);
    syncedRef.current = savedRs;
    if (!hadEdits) setDraft(savedRs);
  }, [savedRs, draft]);

  const dirty = JSON.stringify(draft) !== JSON.stringify(savedRs);

  function patch(p: Partial<RobloxSettingsConfig>) {
    setDraft((d) => ({ ...d, ...p }));
  }
  async function apply() {
    setBusy("apply");
    try {
      await onApply(draft);
    } finally {
      setBusy(null);
    }
  }
  async function restartApply() {
    setBusy("restart");
    try {
      await onRestartApply(draft);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card animate={animate} delay={delay} className="!p-0 overflow-hidden">
      <div className="relative h-[54px] w-full overflow-hidden">
        <img
          src={ROBLOX_ART}
          alt=""
          aria-hidden="true"
          className="absolute inset-0 h-full w-full object-cover"
          style={{
            filter: "blur(16px) brightness(0.5) saturate(1.15)",
            transform: "scale(1.5)",
          }}
          onError={(e) => {
            e.currentTarget.style.display = "none";
          }}
        />
        <div
          className="absolute inset-0"
          style={{ backgroundColor: "rgba(6,6,6,0.45)" }}
        />
        <div className="relative flex h-full items-center justify-between gap-2.5 px-4">
          <div className="flex items-center gap-2.5">
            <span className="text-[14px] font-semibold text-white">Roblox</span>
            <span className="flex items-center gap-1.5">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{
                  backgroundColor: running
                    ? "var(--color-accent-primary)"
                    : "rgba(255,255,255,0.35)",
                  boxShadow: running
                    ? "0 0 6px var(--color-accent-primary-glow)"
                    : "none",
                  animation: running
                    ? "status-breath 1.6s ease-in-out infinite"
                    : "none",
                }}
              />
              <span className="text-[9.5px] font-medium uppercase tracking-[0.06em] text-white/70">
                {running ? "Running" : "Not running"}
              </span>
            </span>
          </div>
          <button
            type="button"
            onClick={onConfigure}
            className="flex items-center gap-1 text-[10.5px] font-medium text-white/70 transition-colors hover:text-white"
          >
            Configure
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M5 12h14M13 6l6 6-6 6" />
            </svg>
          </button>
        </div>
      </div>

      <div className="grid divide-y divide-[color:var(--color-border-subtle)] sm:grid-cols-2 sm:divide-x sm:divide-y-0">
        <ControlRow
          label="Unlock FPS"
          desc="Remove the 60 FPS cap"
          enabled={draft.unlock_fps}
          onChange={(v) => patch({ unlock_fps: v })}
        />
        <ControlRow
          label="Enable FFlags"
          desc="Ultraboost — curated FPS flags"
          enabled={draft.ultraboost}
          onChange={(v) =>
            patch(
              v
                ? { ultraboost: true, custom_fflags_enabled: false }
                : { ultraboost: false },
            )
          }
        />
      </div>
      {draft.unlock_fps && (
        <div
          className="border-t"
          style={{ borderColor: "var(--color-border-subtle)" }}
        >
          <FpsSlider
            value={draft.target_fps}
            onChange={(v) => patch({ target_fps: v })}
          />
        </div>
      )}

      {dirty && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-wrap items-center justify-between gap-2 border-t px-3.5 py-2.5"
          style={{
            borderColor: "var(--color-border-subtle)",
            backgroundColor: "var(--color-bg-elevated)",
          }}
        >
          <span className="text-[11.5px] font-medium text-text-secondary">
            {running
              ? "Roblox must restart for changes to apply"
              : "Unsaved changes"}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setDraft(savedRs)}
              disabled={!!busy}
            >
              Discard
            </Button>
            {running ? (
              <Button
                variant="primary"
                size="sm"
                onClick={() => void restartApply().catch(() => {})}
                loading={busy === "restart"}
                disabled={!!busy}
              >
                Restart &amp; Apply
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                onClick={() => void apply().catch(() => {})}
                loading={busy === "apply"}
                disabled={!!busy}
              >
                Apply
              </Button>
            )}
          </div>
        </motion.div>
      )}
    </Card>
  );
}

function ControlRow({
  label,
  desc,
  enabled,
  onChange,
}: {
  label: string;
  desc: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 px-3.5 py-2">
      <div className="min-w-0">
        <div className="text-[12px] font-medium text-text-primary">{label}</div>
        <div className="text-[10px] leading-snug text-text-muted">{desc}</div>
      </div>
      <Toggle enabled={enabled} ariaLabel={label} onChange={onChange} />
    </div>
  );
}

// ── Shortcuts ──

function ShortcutRow({
  setTab,
  animate,
  delay,
}: {
  setTab: (t: "optimization" | "games" | "ingame" | "repair") => void;
  animate: boolean;
  delay: number;
}) {
  const items = [
    {
      label: "Optimize",
      onClick: () => setTab("optimization"),
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <path d="M13 2L3 14h7l-1 8 10-12h-7z" />
        </svg>
      ),
    },
    {
      label: "Games",
      onClick: () => setTab("games"),
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 12h4M8 10v4M15 11h.01M18 13h.01" />
          <rect x="2" y="6" width="20" height="12" rx="4" />
        </svg>
      ),
    },
    {
      label: "Overlay",
      onClick: () => setTab("ingame"),
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="4" width="18" height="16" rx="2" />
          <rect x="6" y="7" width="7" height="4" rx="1" />
        </svg>
      ),
    },
    {
      label: "Repair",
      onClick: () => setTab("repair"),
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2-2z" />
        </svg>
      ),
    },
  ];
  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-dimmed">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7" rx="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1.5" />
        </svg>
        Shortcuts
      </div>
      <div className="grid grid-cols-4 gap-2">
        {items.map((it, i) => (
          <motion.button
            key={it.label}
            type="button"
            onClick={it.onClick}
            initial={animate ? { opacity: 0, y: 8 } : false}
            animate={animate ? { opacity: 1, y: 0 } : undefined}
            transition={{
              delay: delay + i * 0.03,
              duration: 0.4,
              ease: [0.16, 1, 0.3, 1],
            }}
            className="flex flex-col items-center justify-center gap-1.5 rounded-[var(--radius-card)] surface-card py-3 text-text-secondary transition-all hover:-translate-y-0.5 hover:text-text-primary"
          >
            <span className="icon-orb flex h-9 w-9 items-center justify-center">
              {it.icon}
            </span>
            <span className="text-[10.5px] font-medium">{it.label}</span>
          </motion.button>
        ))}
      </div>
    </div>
  );
}

function CheckCircle({ done }: { done: boolean }) {
  if (done) {
    return (
      <span
        className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full"
        style={{ backgroundColor: "var(--color-accent-primary)" }}
      >
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#0a0a0a" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 12l5 5L20 7" />
        </svg>
      </span>
    );
  }
  return (
    <span
      className="h-[18px] w-[18px] shrink-0 rounded-full"
      style={{ border: "1.5px solid var(--color-border-strong)" }}
    />
  );
}

function ProgressRing({ value, total }: { value: number; total: number }) {
  const pct = total ? value / total : 0;
  const r = 13;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative flex h-9 w-9 shrink-0 items-center justify-center">
      <svg width="36" height="36" viewBox="0 0 36 36" className="-rotate-90">
        <circle cx="18" cy="18" r={r} fill="none" stroke="var(--color-border-subtle)" strokeWidth="3" />
        <motion.circle
          cx="18"
          cy="18"
          r={r}
          fill="none"
          stroke="var(--color-accent-primary)"
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={false}
          animate={{ strokeDashoffset: c * (1 - pct) }}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        />
      </svg>
      <span className="absolute text-[8.5px] font-semibold text-text-secondary">
        {value}/{total}
      </span>
    </div>
  );
}

// ── Network status: run all three probes, show one overall gaming grade ──

function NetworkStatusCard({
  animate,
  delay,
  onConfigure,
}: {
  animate: boolean;
  delay: number;
  onConfigure: () => void;
}) {
  const net = useNetworkStore();

  const statuses = [
    net.stabilityStatus,
    net.speedStatus,
    net.bufferbloatStatus,
  ];
  const anyRunning = statuses.includes("running");
  const started = statuses.some((st) => st !== "idle");
  const settled = started && !anyRunning;
  const doneCount = statuses.filter((st) => st === "complete").length;

  const s = net.stabilityResult;
  const sp = net.speedResult;
  const bb = net.bufferbloatResult;

  // Grade from whatever completed, so one failed probe (e.g. an unreachable
  // speed server) can't leave the card stuck with no result forever.
  const overall = (() => {
    if (!settled) return null;
    const parts: Array<[number, number]> = [];
    if (s) {
      parts.push([scorePing(s.avg_ping), 0.35]);
      parts.push([scoreLoss(s.packet_loss), 0.2]);
    }
    if (bb) parts.push([scoreBloat(bb.bufferbloat_ms), 0.3]);
    if (sp) parts.push([scoreSpeed(sp.download_mbps), 0.15]);
    const weight = parts.reduce((acc, [, w]) => acc + w, 0);
    if (weight === 0) return null;
    const total = parts.reduce((acc, [sc, w]) => acc + sc * w, 0) / weight;
    const grade =
      total >= 90
        ? "A"
        : total >= 75
          ? "B"
          : total >= 60
            ? "C"
            : total >= 45
              ? "D"
              : "F";
    return {
      grade,
      ping: s ? s.avg_ping : null,
      bloat: bb ? bb.bufferbloat_ms : null,
    };
  })();

  const failed = settled && !overall;

  function run() {
    if (anyRunning) return;
    void net.runStabilityTest(10);
    void net.runSpeedTest();
    void net.runBufferbloatTest();
  }

  return (
    <Card animate={animate} delay={delay}>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] font-semibold text-text-primary">
              Network status
            </span>
            <button
              type="button"
              onClick={onConfigure}
              className="flex items-center gap-0.5 text-[10px] font-medium text-text-dimmed transition-colors hover:text-text-secondary"
            >
              Configure
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 6l6 6-6 6" />
              </svg>
            </button>
          </div>
          <div
            className="truncate text-[10.5px]"
            style={{
              color: failed
                ? "var(--color-latency-bad)"
                : "var(--color-text-muted)",
            }}
          >
            {overall
              ? `${gradeName(overall.grade)}${overall.ping !== null ? ` · ${overall.ping.toFixed(0)}ms ping` : ""}${overall.bloat !== null ? ` · +${overall.bloat}ms bloat` : ""}`
              : anyRunning
                ? `Testing… ${doneCount}/3`
                : failed
                  ? "Couldn't reach the test servers — tap retry."
                  : "One grade for your gaming connection."}
          </div>
        </div>
        {overall ? (
          <button
            type="button"
            onClick={run}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
            style={{
              border: `2px solid ${gradeColor(overall.grade)}`,
              boxShadow: `0 0 18px -8px ${gradeColor(overall.grade)}`,
            }}
            aria-label="Test network status again"
          >
            <span
              className="text-[19px] font-bold leading-none"
              style={{ color: gradeColor(overall.grade) }}
            >
              {overall.grade}
            </span>
          </button>
        ) : (
          <button
            type="button"
            onClick={run}
            disabled={anyRunning}
            className="flex shrink-0 items-center gap-1.5 rounded-[8px] px-3 py-1.5 text-[11px] font-semibold transition-opacity disabled:opacity-60"
            style={{ backgroundColor: "var(--color-accent-primary)", color: "#0a0a0a" }}
          >
            {anyRunning && <Spinner size={12} color="#0a0a0a" />}
            {anyRunning ? "Testing…" : failed ? "Retry" : "Test"}
          </button>
        )}
      </div>
    </Card>
  );
}

function scorePing(ms: number) {
  if (ms <= 20) return 100;
  if (ms <= 35) return 88;
  if (ms <= 55) return 72;
  if (ms <= 90) return 55;
  if (ms <= 140) return 38;
  return 22;
}
function scoreBloat(ms: number) {
  if (ms <= 5) return 100;
  if (ms <= 15) return 85;
  if (ms <= 30) return 68;
  if (ms <= 60) return 48;
  return 28;
}
function scoreLoss(pct: number) {
  if (pct <= 0) return 100;
  if (pct < 0.5) return 85;
  if (pct < 1) return 70;
  if (pct < 3) return 45;
  return 20;
}
function scoreSpeed(mbps: number) {
  if (mbps >= 100) return 100;
  if (mbps >= 50) return 88;
  if (mbps >= 25) return 72;
  if (mbps >= 10) return 55;
  if (mbps >= 5) return 40;
  return 25;
}
function gradeColor(grade: string): string {
  switch (grade) {
    case "A":
      return "var(--color-latency-excellent)";
    case "B":
      return "var(--color-latency-good)";
    case "C":
      return "var(--color-latency-fair)";
    default:
      return "var(--color-latency-bad)";
  }
}
function gradeName(grade: string): string {
  switch (grade) {
    case "A":
      return "Excellent";
    case "B":
      return "Good";
    case "C":
      return "Fair";
    case "D":
      return "Poor";
    default:
      return "Weak";
  }
}
