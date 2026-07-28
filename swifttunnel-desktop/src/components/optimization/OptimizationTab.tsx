import { useEffect, useMemo, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { SectionHeader, Row, Toggle, Tooltip, InfoIcon, Spinner, Chip } from "../ui";
import { MemoryCleaner } from "../boost/MemoryCleaner";
import { showRamOverlay } from "../overlay/RamOverlay";
import { useOptimizationStore } from "../../stores/optimizationStore";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useBoostStore } from "../../stores/boostStore";
import { useToastStore } from "../../stores/toastStore";
import {
  nextPowerPlanForSwiftTunnelToggle,
  previousNonSwiftTunnelPowerPlan,
  rememberedPowerPlanForSwiftTunnel,
} from "../boost/boostConfig";
import type { Config } from "../../lib/types";
import {
  OPTIMIZATIONS,
  SPEEDUP_OPTIMIZATIONS,
  SPEEDUP_CATEGORY_ORDER,
  TIER_ORDER,
  TIER_DESCRIPTION,
  type OptimizationDef,
  type OptCategory,
  type OptTier,
  type SpeedUpCategory,
  type SpeedUpDef,
} from "./optimizationCatalog";

/** Cards shown per carousel page (2 columns x 2 rows). */
const CARDS_PER_PAGE = 4;

/** One summary toast for a bulk apply/revert instead of one toast per item. */
function summarizeBulk(
  verb: string,
  changed: number,
  failed: number,
  reboot: number,
) {
  if (changed === 0 && failed === 0) return;
  const parts = [`${verb} ${changed} ${changed === 1 ? "tweak" : "tweaks"}`];
  if (failed > 0) parts.push(`${failed} failed`);
  if (reboot > 0) parts.push(`${reboot} need a restart`);
  useToastStore.getState().addToast({
    type: failed > 0 ? "warning" : "success",
    message: parts.join(" · "),
  });
}

/** Small category chip shown on each card. */
function CategoryChip({ category }: { category: OptCategory }) {
  return (
    <Chip size="xs" tone={category === "Performance" ? "accent" : "neutral"}>
      {category === "Performance" ? "FPS & Latency" : category}
    </Chip>
  );
}

/** The (i) tooltip: exactly what this optimization changes, plus any
 *  admin/restart requirement. Mirrors the boost page's info affordance. */
function changesTooltip(def: {
  changes: string[];
  requiresAdmin: boolean;
  requiresReboot: boolean;
}): ReactNode {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[10.5px] font-semibold uppercase tracking-[0.07em] text-text-dimmed">
        What changes
      </span>
      <ul className="flex flex-col gap-0.5">
        {def.changes.map((change) => (
          <li key={change} className="font-mono text-[10.5px] leading-snug">
            {change}
          </li>
        ))}
      </ul>
      {(def.requiresAdmin || def.requiresReboot) && (
        <span className="text-[10px] text-text-muted">
          {[
            def.requiresAdmin ? "Needs administrator" : null,
            def.requiresReboot ? "Needs restart" : null,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      )}
      <span className="text-[10px] text-text-muted">
        Reversible, turning this off restores the previous values.
      </span>
    </div>
  );
}

/** Hone-style caution / restart badges shown on a card. */
function CardBadges({ def }: { def: OptimizationDef }) {
  const badges: ReactNode[] = [];
  if (def.safety === "caution" || def.requiresAdmin) {
    badges.push(
      <Tooltip
        key="caution"
        content={
          def.requiresAdmin
            ? "Changes a system-wide setting (administrator)."
            : "Trades a Windows feature for performance."
        }
      >
        <span
          className="inline-flex h-[18px] w-[18px] items-center justify-center rounded-[5px]"
          style={{
            backgroundColor: "rgba(245, 158, 11, 0.12)",
            border: "1px solid rgba(245, 158, 11, 0.35)",
          }}
        >
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 3 2.5 20h19L12 3Z"
              stroke="#f59e0b"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path d="M12 10v4.5" stroke="#f59e0b" strokeWidth="2" strokeLinecap="round" />
            <circle cx="12" cy="17.4" r="1.1" fill="#f59e0b" />
          </svg>
        </span>
      </Tooltip>,
    );
  }
  if (def.requiresReboot) {
    badges.push(
      <Tooltip key="reboot" content="Takes effect after a restart or sign-out.">
        <span
          className="inline-flex h-[18px] w-[18px] items-center justify-center rounded-[5px]"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none">
            <path
              d="M20 12a8 8 0 1 1-2.3-5.6"
              stroke="var(--color-text-muted)"
              strokeWidth="2"
              strokeLinecap="round"
            />
            <path
              d="M20 3v4h-4"
              stroke="var(--color-text-muted)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </Tooltip>,
    );
  }
  if (badges.length === 0) return null;
  return <span className="flex items-center gap-1">{badges}</span>;
}

const CARD_DESCRIPTION_CLAMP: React.CSSProperties = {
  display: "-webkit-box",
  WebkitLineClamp: 3,
  WebkitBoxOrient: "vertical",
  overflow: "hidden",
};

function CardShell({
  children,
  anchor,
  active,
}: {
  children: ReactNode;
  anchor?: string;
  /** Applied tweak, lights the card's left rail so an active grid is
   *  scannable at a glance instead of hunting for toggle positions. */
  active?: boolean;
}) {
  return (
    <div
      data-search-anchor={anchor}
      className="surface-card relative flex min-h-[148px] flex-col gap-1.5 overflow-hidden rounded-[var(--radius-card)] px-3 pb-2.5 pt-3 transition-transform duration-150 hover:-translate-y-0.5"
      style={{
        border: `1px solid ${
          active
            ? "var(--color-status-connected-soft-20)"
            : "var(--color-border-subtle)"
        }`,
      }}
    >
      {active && (
        <span
          aria-hidden
          className="absolute inset-y-0 left-0 w-[2px]"
          style={{
            background: "var(--color-status-connected)",
            boxShadow: "0 0 12px -2px var(--color-status-connected)",
          }}
        />
      )}
      {children}
    </div>
  );
}

function CardFooter({
  tooltip,
  busy,
  enabled,
  disabled,
  ariaLabel,
  onChange,
}: {
  tooltip: ReactNode;
  busy: boolean;
  enabled: boolean;
  disabled?: boolean;
  ariaLabel: string;
  onChange: (next: boolean) => void;
}) {
  return (
    <div
      className="mt-auto flex items-center justify-between gap-2 pt-2"
      style={{ borderTop: "1px solid var(--color-border-subtle)" }}
    >
      <Tooltip content={tooltip}>
        <span className="inline-flex">
          <InfoIcon />
        </span>
      </Tooltip>
      <div className="flex items-center gap-2">
        {busy && <Spinner size={11} color="var(--color-accent-primary)" />}
        <span className="text-[10px] font-medium text-text-muted">Activate</span>
        <Toggle
          enabled={enabled}
          disabled={disabled}
          ariaLabel={ariaLabel}
          onChange={onChange}
        />
      </div>
    </div>
  );
}

function OptimizationCard({ def }: { def: OptimizationDef }) {
  const status = useOptimizationStore((s) => s.status[def.id] ?? "inactive");
  const activate = useOptimizationStore((s) => s.activate);
  const deactivate = useOptimizationStore((s) => s.deactivate);

  const isActive = status === "active";
  const isBusy = status === "activating" || status === "deactivating";

  return (
    <CardShell anchor={def.id} active={isActive}>
      <div className="flex items-center justify-between gap-2">
        <CategoryChip category={def.category} />
        <CardBadges def={def} />
      </div>
      <h4 className="text-[12px] font-semibold leading-snug text-text-primary">
        {def.name}
      </h4>
      <p
        className="text-[10.5px] leading-snug text-text-muted"
        style={CARD_DESCRIPTION_CLAMP}
      >
        {def.description}
      </p>
      <CardFooter
        tooltip={changesTooltip(def)}
        busy={isBusy}
        enabled={isActive}
        disabled={isBusy}
        ariaLabel={def.name}
        onChange={(next) => {
          if (next) void activate(def);
          else void deactivate(def);
        }}
      />
    </CardShell>
  );
}

/** SwiftTunnel power plan lives in the boost config (it swaps the active
 *  Windows power scheme and remembers the previous one), so it applies
 *  immediately through the boost backend rather than the optimization
 *  apply/revert commands. Shown as the first card of the Intermediate tier. */
function PowerPlanCard() {
  const config = useSettingsStore((s) => s.settings.config);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const updateConfig = useBoostStore((s) => s.updateConfig);
  const addToast = useToastStore((s) => s.addToast);
  const [busy, setBusy] = useState(false);

  const enabled = config.system_optimization.power_plan === "SwiftTunnel";

  async function toggle(next: boolean) {
    const current = config.system_optimization.power_plan;
    const remembered = previousNonSwiftTunnelPowerPlan(
      next && current !== "SwiftTunnel"
        ? current
        : rememberedPowerPlanForSwiftTunnel(
            current,
            config.system_optimization.previous_power_plan,
          ),
    );
    const nextConfig: Config = {
      ...config,
      system_optimization: {
        ...config.system_optimization,
        power_plan: nextPowerPlanForSwiftTunnelToggle(next, remembered),
        previous_power_plan: remembered,
      },
    };

    setBusy(true);
    try {
      const applied = await updateConfig(JSON.stringify(nextConfig));
      updateSettings({ config: applied });
      void saveSettings();
      addToast({
        type: next ? "success" : "info",
        message: next
          ? "SwiftTunnel power plan activated"
          : "Previous power plan restored",
      });
    } catch {
      // updateConfig already surfaces the error through the boost store.
    } finally {
      setBusy(false);
    }
  }

  return (
    <CardShell>
      <div className="flex items-center justify-between gap-2">
        <CategoryChip category="Performance" />
      </div>
      <h4 className="text-[12px] font-semibold leading-snug text-text-primary">
        SwiftTunnel Power Plan
      </h4>
      <p
        className="text-[10.5px] leading-snug text-text-muted"
        style={CARD_DESCRIPTION_CLAMP}
      >
        Activates SwiftTunnel's low-latency Windows power profile. Your previous
        plan is remembered and restored when you turn this off.
      </p>
      <CardFooter
        tooltip="Imports and activates SwiftTunnel's optimized power plan. Your previous power plan is remembered and restored when you turn this off."
        busy={busy}
        enabled={enabled}
        disabled={busy}
        ariaLabel="SwiftTunnel Power Plan"
        onChange={(next) => void toggle(next)}
      />
    </CardShell>
  );
}

/** One tier card: either a backend optimization or the special power plan. */
type TierCard =
  | { key: string; kind: "opt"; def: OptimizationDef }
  | { key: string; kind: "power" };

function chunk<T>(items: T[], size: number): T[][] {
  const pages: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    pages.push(items.slice(i, i + size));
  }
  return pages;
}

function ChevronButton({
  direction,
  disabled,
  onClick,
}: {
  direction: "prev" | "next";
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={direction === "prev" ? "Previous page" : "Next page"}
      disabled={disabled}
      onClick={onClick}
      className="inline-flex h-6 w-6 items-center justify-center rounded-[7px] transition-colors disabled:cursor-not-allowed disabled:opacity-35"
      style={{
        border: "1px solid var(--color-border-subtle)",
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-secondary)",
      }}
    >
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none">
        <path
          d={direction === "prev" ? "M14.5 5 8 12l6.5 7" : "M9.5 5 16 12l-6.5 7"}
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}

/** A tier section: header with < > pagination, and an animated 2x2 card grid
 *  that slides between pages (Hone-style). */
function TierCarousel({ tier, cards }: { tier: OptTier; cards: TierCard[] }) {
  const statuses = useOptimizationStore((s) => s.status);
  const powerPlanEnabled = useSettingsStore(
    (s) => s.settings.config.system_optimization.power_plan === "SwiftTunnel",
  );
  const deepLinkAnchor = useDeepLinkStore((s) => s.anchor);
  const [page, setPage] = useState(0);

  const pages = useMemo(() => chunk(cards, CARDS_PER_PAGE), [cards]);
  const pageCount = pages.length;
  const current = Math.min(page, pageCount - 1);

  // Deep-link: if a search targeted one of our cards, page to it so it's
  // on-screen when the highlight flashes.
  useEffect(() => {
    if (!deepLinkAnchor) return;
    const idx = pages.findIndex((pg) =>
      pg.some((c) => c.kind === "opt" && c.def.id === deepLinkAnchor),
    );
    if (idx >= 0) setPage(idx);
  }, [deepLinkAnchor, pages]);

  const activeCount = cards.filter((card) =>
    card.kind === "power" ? powerPlanEnabled : statuses[card.def.id] === "active",
  ).length;
  const optDefs = cards.flatMap((card) =>
    card.kind === "opt" ? [card.def] : [],
  );

  const go = (delta: number) => {
    setPage((p) =>
      Math.max(0, Math.min(pageCount - 1, Math.min(p, pageCount - 1) + delta)),
    );
  };

  return (
    <section>
      <div className="flex items-end justify-between gap-3">
        <SectionHeader
          label={tier}
          tag={`${activeCount} / ${cards.length} on`}
          inlineAction={<BulkToggle items={optDefs} />}
          description={TIER_DESCRIPTION[tier]}
        />
        {pageCount > 1 && (
          <div className="mb-2 flex shrink-0 items-center gap-1.5">
            <ChevronButton
              direction="prev"
              disabled={current === 0}
              onClick={() => go(-1)}
            />
            <span className="min-w-[34px] text-center font-mono text-[9.5px] text-text-muted">
              {current + 1} / {pageCount}
            </span>
            <ChevronButton
              direction="next"
              disabled={current >= pageCount - 1}
              onClick={() => go(1)}
            />
          </div>
        )}
      </div>

      {/* A single track holding every page side-by-side; we slide the whole
          strip by one viewport per page so it reads as a real carousel rather
          than the cards snapping to the next set. */}
      <div className="relative overflow-hidden">
        <motion.div
          className="flex"
          style={{ width: `${pageCount * 100}%` }}
          animate={{ x: `${(-current * 100) / pageCount}%` }}
          transition={{ duration: 0.34, ease: [0.32, 0.72, 0, 1] }}
        >
          {pages.map((pageCards, idx) => (
            <div
              key={idx}
              className="shrink-0"
              style={{ width: `${100 / pageCount}%` }}
              aria-hidden={idx !== current}
            >
              <div className="grid grid-cols-2 gap-2.5">
                {pageCards.map((card) =>
                  card.kind === "power" ? (
                    <PowerPlanCard key={card.key} />
                  ) : (
                    <OptimizationCard key={card.key} def={card.def} />
                  ),
                )}
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

/** Order cards inside a tier so categories cluster visually. */
const CATEGORY_SORT_ORDER: OptCategory[] = [
  "Performance",
  "Input",
  "System",
  "Privacy",
];

function tierCards(tier: OptTier): TierCard[] {
  const defs = OPTIMIZATIONS.filter((d) => d.tier === tier).sort(
    (a, b) =>
      CATEGORY_SORT_ORDER.indexOf(a.category) -
      CATEGORY_SORT_ORDER.indexOf(b.category),
  );
  const cards: TierCard[] = defs.map((def) => ({
    key: def.id,
    kind: "opt",
    def,
  }));
  // The SwiftTunnel power plan is a power/performance tweak; surface it at the
  // top of the Intermediate tier (it applies via the boost backend, not the
  // optimization apply/revert commands).
  if (tier === "Intermediate") {
    cards.unshift({ key: "swifttunnel_power_plan", kind: "power" });
  }
  return cards;
}

/** Auto-clean RAM when a game launches; result shows in the in-game overlay. */
function AutoRamCleanRow() {
  const config = useSettingsStore((s) => s.settings.config);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const updateConfig = useBoostStore((s) => s.updateConfig);
  const addToast = useToastStore((s) => s.addToast);
  const [busy, setBusy] = useState(false);

  const enabled = config.system_optimization.auto_ram_clean;

  async function preview() {
    try {
      await showRamOverlay(4096);
      addToast({
        type: "info",
        message: "Test overlay sent, check the top-right of your screen.",
      });
    } catch (e) {
      addToast({
        type: "error",
        message: e instanceof Error ? e.message : "Could not show the overlay.",
      });
    }
  }

  async function toggle(next: boolean) {
    const nextConfig: Config = {
      ...config,
      system_optimization: {
        ...config.system_optimization,
        auto_ram_clean: next,
      },
    };
    setBusy(true);
    try {
      const applied = await updateConfig(JSON.stringify(nextConfig));
      updateSettings({ config: applied });
      void saveSettings();
    } catch {
      // updateConfig surfaces errors through the boost store.
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="instrument overflow-hidden">
      <Row
        label="Auto-clean RAM on game launch"
        desc="Frees standby memory automatically when a game starts, with an in-game overlay."
        tooltip={
          <span className="flex items-center gap-1.5">
            <CategoryChip category="System" />
            <Tooltip content="When a game launches, SwiftTunnel trims standby/working-set memory (excluding the game) and shows a 'RAM freed' overlay in the corner of your screen.">
              <span className="inline-flex">
                <InfoIcon />
              </span>
            </Tooltip>
          </span>
        }
      >
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void preview()}
            className="rounded-[6px] px-2 py-1 text-[10.5px] font-medium text-text-muted transition-colors hover:text-text-primary"
            style={{
              border: "1px solid var(--color-border-subtle)",
              backgroundColor: "var(--color-bg-elevated)",
            }}
          >
            Preview
          </button>
          {busy && <Spinner size={11} color="var(--color-accent-primary)" />}
          <Toggle
            enabled={enabled}
            disabled={busy}
            ariaLabel="Auto-clean RAM on game launch"
            onChange={(next) => void toggle(next)}
          />
        </div>
      </Row>
    </div>
  );
}

export function OptimizationTab() {
  const loadActive = useOptimizationStore((s) => s.loadActive);
  const [view, setView] = useState<"boost" | "speedup">("boost");
  const deepLinkAnchor = useDeepLinkStore((s) => s.anchor);

  // Reflect which optimizations are already applied (persisted on disk).
  useEffect(() => {
    void loadActive();
  }, [loadActive]);

  // Deep-link: switch to whichever sub-tab owns the searched optimization.
  useEffect(() => {
    if (!deepLinkAnchor) return;
    if (SPEEDUP_OPTIMIZATIONS.some((o) => o.id === deepLinkAnchor)) {
      setView("speedup");
    } else if (OPTIMIZATIONS.some((o) => o.id === deepLinkAnchor)) {
      setView("boost");
    }
  }, [deepLinkAnchor]);

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      {/* Sub-tabs + restore-to-defaults. */}
      <div className="flex items-center justify-between gap-3">
        <div
          className="flex w-fit items-center gap-1 rounded-[10px] p-1"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          {(["boost", "speedup"] as const).map((v) => (
            <button
              key={v}
              type="button"
              onClick={() => setView(v)}
              className="rounded-[7px] px-4 py-1.5 text-[12px] font-medium transition-colors"
              style={{
                backgroundColor:
                  view === v ? "var(--color-bg-active)" : "transparent",
                color:
                  view === v
                    ? "var(--color-text-primary)"
                    : "var(--color-text-muted)",
              }}
            >
              {v === "boost" ? "Game Boost" : "Speed Up"}
            </button>
          ))}
        </div>
        <RestoreDefaultsButton />
      </div>

      {/* Scoped to the active sub-tab ("N tweaks ready · Game Boost"), so it
          belongs UNDER the switcher, above it, it read as a page header that
          silently changed meaning when you switched sub-tabs. */}
      <OptimizeAllHeader view={view} />

      {/* RAM cleaner stays mounted across both sub-tabs. */}
      <MemoryCleaner />

      {view === "boost" ? (
        <>
          <AutoRamCleanRow />
          {TIER_ORDER.map((tier) => {
            const cards = tierCards(tier);
            if (cards.length === 0) return null;
            return <TierCarousel key={tier} tier={tier} cards={cards} />;
          })}
        </>
      ) : (
        <SpeedUpView />
      )}
    </div>
  );
}

function RocketIcon() {
  return (
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-accent-primary)"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z" />
      <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z" />
      <path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0" />
      <path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5" />
    </svg>
  );
}

/** "Enable all" for a section, flips to "Disable all" once every item is on. */
function BulkToggle({ items }: { items: { id: string; name: string }[] }) {
  const statuses = useOptimizationStore((s) => s.status);
  const activate = useOptimizationStore((s) => s.activate);
  const deactivate = useOptimizationStore((s) => s.deactivate);
  const [busy, setBusy] = useState(false);

  if (items.length === 0) return null;

  const allActive = items.every((i) => statuses[i.id] === "active");
  const inFlight =
    busy ||
    items.some((i) => {
      const s = statuses[i.id];
      return s === "activating" || s === "deactivating";
    });

  async function toggleAll() {
    if (busy) return;
    setBusy(true);
    try {
      let changed = 0;
      let failed = 0;
      let reboot = 0;
      for (const item of items) {
        const active = statuses[item.id] === "active";
        let outcome = null;
        if (allActive && active) outcome = await deactivate(item, { silent: true });
        else if (!allActive && !active)
          outcome = await activate(item, { silent: true });
        if (!outcome) continue;
        if (!outcome.ok) failed += 1;
        else {
          changed += 1;
          if (outcome.requiresReboot) reboot += 1;
        }
      }
      summarizeBulk(allActive ? "Reverted" : "Enabled", changed, failed, reboot);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        void toggleAll();
      }}
      disabled={inFlight}
      className="shrink-0 rounded-[6px] px-2 py-[3px] text-[10px] font-semibold uppercase tracking-[0.04em] transition-colors hover:bg-bg-hover disabled:opacity-50"
      style={{
        border: "1px solid var(--color-border-subtle)",
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-secondary)",
      }}
    >
      {allActive ? "Disable all" : "Enable all"}
    </button>
  );
}

/** Reverts every applied optimization (both sub-tabs) back to Windows defaults. */
function RestoreDefaultsButton() {
  const statuses = useOptimizationStore((s) => s.status);
  const deactivate = useOptimizationStore((s) => s.deactivate);
  const [busy, setBusy] = useState(false);

  const active = [...OPTIMIZATIONS, ...SPEEDUP_OPTIMIZATIONS].filter(
    (o) => statuses[o.id] === "active",
  );

  async function restore() {
    if (busy || active.length === 0) return;
    setBusy(true);
    try {
      let changed = 0;
      let failed = 0;
      let reboot = 0;
      for (const item of active) {
        const outcome = await deactivate(
          { id: item.id, name: item.name },
          { silent: true },
        );
        if (!outcome.ok) failed += 1;
        else {
          changed += 1;
          if (outcome.requiresReboot) reboot += 1;
        }
      }
      summarizeBulk("Restored", changed, failed, reboot);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      onClick={() => void restore()}
      disabled={busy || active.length === 0}
      title="Revert every applied optimization back to Windows defaults"
      className="flex shrink-0 items-center gap-1.5 rounded-[8px] px-3 py-1.5 text-[11.5px] font-medium transition-colors hover:bg-bg-hover disabled:opacity-45"
      style={{ color: "var(--color-text-muted)" }}
    >
      <svg
        width="13"
        height="13"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={busy ? "animate-spin" : ""}
        aria-hidden
      >
        <path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
        <path d="M21 3v5h-5" />
        <path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
        <path d="M3 21v-5h5" />
      </svg>
      {busy ? "Restoring…" : "Restore Windows defaults"}
    </button>
  );
}

/** Razer-style hero: count of pending tweaks + a one-click "Optimize all". */
function OptimizeAllHeader({ view }: { view: "boost" | "speedup" }) {
  const statuses = useOptimizationStore((s) => s.status);
  const activate = useOptimizationStore((s) => s.activate);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);

  const pending = useMemo(() => {
    if (view === "speedup") {
      return SPEEDUP_OPTIMIZATIONS.filter((o) => statuses[o.id] !== "active");
    }
    // Game Boost bulk-apply skips "caution" tweaks, those stay opt-in.
    return OPTIMIZATIONS.filter(
      (o) => o.safety !== "caution" && statuses[o.id] !== "active",
    );
  }, [view, statuses]);

  const total = pending.length;

  async function optimizeAll() {
    if (running || total === 0) return;
    setRunning(true);
    setProgress(0);
    try {
      let done = 0;
      let failed = 0;
      let reboot = 0;
      for (const def of pending) {
        const outcome = await activate(
          { id: def.id, name: def.name },
          { silent: true },
        );
        if (!outcome.ok) failed += 1;
        else if (outcome.requiresReboot) reboot += 1;
        done += 1;
        setProgress(done);
      }
      summarizeBulk("Optimized", done - failed, failed, reboot);
    } finally {
      setRunning(false);
    }
  }

  const label = running
    ? `Optimizing… ${progress}/${total}`
    : total === 0
      ? "All optimized"
      : "Optimize all";

  return (
    <section
      className="corner-frame relative flex items-center justify-between gap-4 overflow-hidden rounded-[var(--radius-card)] surface-card"
      style={{ padding: "16px 20px" }}
    >
      <div
        aria-hidden="true"
        className="dot-grid pointer-events-none absolute inset-0"
        style={{ opacity: 0.55 }}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(circle at 14% 8%, var(--color-accent-primary-soft-12), transparent 34%)",
        }}
      />
      <div className="relative z-[1] flex min-w-0 items-center gap-3.5">
        <span
          className="icon-orb neon-edge flex h-12 w-12 shrink-0 items-center justify-center"
          style={{
            backgroundColor: "var(--color-accent-primary-soft-12)",
            color: "var(--color-accent-primary)",
          }}
        >
          <RocketIcon />
        </span>
        <div className="min-w-0">
          <h2 className="text-[16px] font-semibold leading-tight text-text-primary">
            {total === 0
              ? "Everything's optimized"
              : `${total} ${total === 1 ? "tweak" : "tweaks"} ready to optimize`}
          </h2>
          <p className="mt-0.5 text-[11.5px] leading-snug text-text-muted">
            {view === "speedup" ? "Speed Up" : "Game Boost"} · one click applies
            them all, every change is reversible.
          </p>
        </div>
      </div>
      <button
        type="button"
        onClick={() => void optimizeAll()}
        disabled={running || total === 0}
        className="repair-cta relative z-[1] flex shrink-0 items-center overflow-hidden rounded-[10px] px-5 py-2.5 text-[13px] font-semibold transition-all duration-150 disabled:cursor-not-allowed disabled:opacity-60"
        style={{
          background: "linear-gradient(180deg, #ffffff 0%, #e9e9e9 100%)",
          color: "#0a0a0a",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.9), 0 2px 10px rgba(0,0,0,0.35)",
        }}
      >
        <span className="relative z-[1] flex items-center gap-2">
          {running && <Spinner size={14} color="#0a0a0a" />}
          {label}
        </span>
      </button>
    </section>
  );
}

/** Speed Up sub-tab: optimizations grouped by category in collapsible sections. */
function SpeedUpView() {
  return (
    <div className="flex w-full flex-col gap-4">
      {SPEEDUP_CATEGORY_ORDER.map((cat) => {
        const items = SPEEDUP_OPTIMIZATIONS.filter((o) => o.category === cat);
        if (items.length === 0) return null;
        return <SpeedUpSection key={cat} category={cat} items={items} />;
      })}
    </div>
  );
}

function SpeedUpSection({
  category,
  items,
}: {
  category: SpeedUpCategory;
  items: SpeedUpDef[];
}) {
  const statuses = useOptimizationStore((s) => s.status);
  const anchor = useDeepLinkStore((s) => s.anchor);
  const activeCount = items.filter((i) => statuses[i.id] === "active").length;
  const [open, setOpen] = useState(true);

  // Expand if a search deep-linked to one of this section's items.
  useEffect(() => {
    if (anchor && items.some((i) => i.id === anchor)) setOpen(true);
  }, [anchor, items]);

  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 items-center gap-2"
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--color-text-muted)"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{
              transform: open ? "rotate(90deg)" : "none",
              transition: "transform 0.15s ease",
            }}
          >
            <path d="M9 6l6 6-6 6" />
          </svg>
          <span className="text-[13px] font-semibold text-text-primary">
            {category}
          </span>
          <span className="pill-base">
            {activeCount} / {items.length} on
          </span>
        </button>
        <BulkToggle items={items} />
      </div>
      {open && (
        <div className="instrument p-1.5">
          <div className="grid grid-cols-1 gap-x-4 gap-y-0.5 sm:grid-cols-2">
            {items.map((def) => (
              <SpeedUpItem key={def.id} def={def} />
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

/** One optimization in the 2-up grid: a check indicator + name/description,
 *  click anywhere to toggle. */
function SpeedUpItem({ def }: { def: SpeedUpDef }) {
  const status = useOptimizationStore((s) => s.status[def.id] ?? "inactive");
  const activate = useOptimizationStore((s) => s.activate);
  const deactivate = useOptimizationStore((s) => s.deactivate);
  const isActive = status === "active";
  const isBusy = status === "activating" || status === "deactivating";

  return (
    <button
      type="button"
      data-search-anchor={def.id}
      onClick={() => {
        if (isBusy) return;
        if (isActive) void deactivate(def);
        else void activate(def);
      }}
      className="flex items-start gap-2.5 rounded-[8px] px-2 py-1.5 text-left transition-colors hover:bg-[color:var(--color-bg-hover)]"
    >
      <span
        className="mt-[1px] flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full transition-colors"
        style={{
          backgroundColor: isActive
            ? "var(--color-accent-primary)"
            : "transparent",
          border: isActive ? "none" : "1.5px solid var(--color-border-strong)",
        }}
      >
        {isBusy ? (
          <Spinner size={11} color="var(--color-accent-primary)" />
        ) : isActive ? (
          <svg
            width="11"
            height="11"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#0a0a0a"
            strokeWidth="3.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M20 6 9 17l-5-5" />
          </svg>
        ) : null}
      </span>
      <span className="min-w-0">
        <span className="block text-[12px] font-medium text-text-primary">
          {def.name}
        </span>
        <span className="block text-[10.5px] leading-snug text-text-muted">
          {def.description}
        </span>
      </span>
    </button>
  );
}
