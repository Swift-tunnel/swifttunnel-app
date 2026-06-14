import { useEffect, useMemo, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { SectionHeader, Row, Toggle, Tooltip, InfoIcon, Spinner, Chip } from "../ui";
import { MemoryCleaner } from "../boost/MemoryCleaner";
import { showRamOverlay } from "../overlay/RamOverlay";
import { useOptimizationStore } from "../../stores/optimizationStore";
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
  TIER_ORDER,
  TIER_DESCRIPTION,
  type OptimizationDef,
  type OptCategory,
  type OptTier,
} from "./optimizationCatalog";

/** Cards shown per carousel page (2 columns x 2 rows). */
const CARDS_PER_PAGE = 4;

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
function changesTooltip(def: OptimizationDef): ReactNode {
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
        Reversible — turning this off restores the previous values.
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

function CardShell({ children }: { children: ReactNode }) {
  return (
    <div
      className="surface-card flex min-h-[148px] flex-col gap-1.5 rounded-[var(--radius-card)] px-3 pb-2.5 pt-3"
      style={{ border: "1px solid var(--color-border-subtle)" }}
    >
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
    <CardShell>
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
  const [page, setPage] = useState(0);

  const pages = useMemo(() => chunk(cards, CARDS_PER_PAGE), [cards]);
  const pageCount = pages.length;
  const current = Math.min(page, pageCount - 1);

  const activeCount = cards.filter((card) =>
    card.kind === "power" ? powerPlanEnabled : statuses[card.def.id] === "active",
  ).length;

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
        message: "Test overlay sent - check the top-right of your screen.",
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
    <div className="overflow-hidden rounded-[var(--radius-card)] surface-card">
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

  // Reflect which optimizations are already applied (persisted on disk).
  useEffect(() => {
    void loadActive();
  }, [loadActive]);

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      <MemoryCleaner />
      <AutoRamCleanRow />

      {TIER_ORDER.map((tier) => {
        const cards = tierCards(tier);
        if (cards.length === 0) return null;
        return <TierCarousel key={tier} tier={tier} cards={cards} />;
      })}
    </div>
  );
}
