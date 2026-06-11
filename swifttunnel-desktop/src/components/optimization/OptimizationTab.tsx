import { useEffect, useState, type ReactNode } from "react";
import {
  SectionHeader,
  Row,
  Toggle,
  Tooltip,
  InfoIcon,
  Spinner,
  Chip,
} from "../ui";
import { MemoryCleaner } from "../boost/MemoryCleaner";
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

/** Small category chip shown next to each optimization name. */
function CategoryChip({ category }: { category: OptCategory }) {
  return (
    <Chip size="xs" tone={category === "Performance" ? "accent" : "neutral"}>
      {category}
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

const CATEGORY_GROUP_ORDER: OptCategory[] = [
  "Performance",
  "Input",
  "System",
  "Privacy",
];

const CATEGORY_GROUP_META: Record<
  OptCategory,
  { label: string; description: string }
> = {
  Performance: {
    label: "FPS / Latency",
    description: "Frame pacing, power, GPU, and game-service tweaks.",
  },
  Input: {
    label: "Input",
    description: "Mouse and control feel tweaks.",
  },
  System: {
    label: "System",
    description: "Windows behavior and background workload tweaks.",
  },
  Privacy: {
    label: "Privacy",
    description: "Telemetry and background data collection tweaks.",
  },
};

function OptimizationRow({ def }: { def: OptimizationDef }) {
  const status = useOptimizationStore((s) => s.status[def.id] ?? "inactive");
  const activate = useOptimizationStore((s) => s.activate);
  const deactivate = useOptimizationStore((s) => s.deactivate);

  const isActive = status === "active";
  const isBusy = status === "activating" || status === "deactivating";

  return (
    <Row
      label={def.name}
      desc={def.description}
      tooltip={
        <span className="flex items-center gap-1.5">
          <CategoryChip category={def.category} />
          <Tooltip content={changesTooltip(def)}>
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
        </span>
      }
    >
      <div className="flex items-center gap-2">
        {isBusy && (
          <Spinner size={11} color="var(--color-accent-primary)" />
        )}
        <Toggle
          enabled={isActive}
          disabled={isBusy}
          ariaLabel={def.name}
          onChange={(next) => {
            if (next) void activate(def);
            else void deactivate(def);
          }}
        />
      </div>
    </Row>
  );
}

/** SwiftTunnel power plan lives in the boost config (it swaps the active
 *  Windows power scheme and remembers the previous one), so it applies
 *  immediately through the boost backend rather than the optimization
 *  apply/revert commands. */
function PowerPlanRow() {
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
    <Row
      label="SwiftTunnel Power Plan"
      desc="Custom low-latency Windows power profile"
      tooltip={
        <span className="flex items-center gap-1.5">
          <CategoryChip category="Performance" />
          <Tooltip content="Imports and activates SwiftTunnel's optimized power plan. Your previous power plan is remembered and restored when you turn this off.">
            <span className="inline-flex">
              <InfoIcon />
            </span>
          </Tooltip>
        </span>
      }
    >
      <div className="flex items-center gap-2">
        {busy && <Spinner size={11} color="var(--color-accent-primary)" />}
        <Toggle
          enabled={enabled}
          disabled={busy}
          ariaLabel="SwiftTunnel Power Plan"
          onChange={(next) => void toggle(next)}
        />
      </div>
    </Row>
  );
}

function OptimizationTierGroup({
  tier,
  defs,
}: {
  tier: OptTier;
  defs: OptimizationDef[];
}) {
  const statuses = useOptimizationStore((s) => s.status);
  const powerPlanEnabled = useSettingsStore(
    (s) => s.settings.config.system_optimization.power_plan === "SwiftTunnel",
  );
  // The SwiftTunnel power plan is a power/performance tweak; surface it at the
  // top of the Intermediate tier (it applies via the boost backend, not the
  // optimization apply/revert commands).
  const includesPowerPlan = tier === "Intermediate";
  const activeCount =
    defs.filter((d) => statuses[d.id] === "active").length +
    (includesPowerPlan && powerPlanEnabled ? 1 : 0);
  const total = defs.length + (includesPowerPlan ? 1 : 0);
  const groups = CATEGORY_GROUP_ORDER.map((category) => ({
    category,
    defs: defs.filter((d) => d.category === category),
    includesPowerPlan: includesPowerPlan && category === "Performance",
  })).filter((group) => group.defs.length > 0 || group.includesPowerPlan);

  return (
    <section>
      <SectionHeader
        label={tier}
        tag={`${activeCount} / ${total} on`}
        description={TIER_DESCRIPTION[tier]}
      />
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card">
        {groups.map((group) => (
          <OptimizationCategoryGroup
            key={group.category}
            category={group.category}
            defs={group.defs}
            includesPowerPlan={group.includesPowerPlan}
          />
        ))}
      </div>
    </section>
  );
}

function OptimizationCategoryGroup({
  category,
  defs,
  includesPowerPlan,
}: {
  category: OptCategory;
  defs: OptimizationDef[];
  includesPowerPlan: boolean;
}) {
  const statuses = useOptimizationStore((s) => s.status);
  const powerPlanEnabled = useSettingsStore(
    (s) => s.settings.config.system_optimization.power_plan === "SwiftTunnel",
  );
  const meta = CATEGORY_GROUP_META[category];
  const activeCount =
    defs.filter((d) => statuses[d.id] === "active").length +
    (includesPowerPlan && powerPlanEnabled ? 1 : 0);
  const total = defs.length + (includesPowerPlan ? 1 : 0);

  return (
    <div className="border-b border-[color:var(--color-border-subtle)] last:border-b-0">
      <div className="flex items-end justify-between gap-3 px-3.5 pb-2 pt-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="eyebrow text-text-secondary">{meta.label}</h4>
            <span
              className="rounded-[4px] px-1.5 py-[2px] font-mono text-[9.5px] font-medium leading-none"
              style={{
                backgroundColor: "var(--color-bg-elevated)",
                color: "var(--color-text-muted)",
                border: "1px solid var(--color-border-subtle)",
              }}
            >
              {activeCount} / {total}
            </span>
          </div>
          <p className="mt-1 text-[10.5px] leading-snug text-text-muted">
            {meta.description}
          </p>
        </div>
      </div>
      <div className="divide-y divide-[color:var(--color-border-subtle)]">
        {includesPowerPlan && <PowerPlanRow />}
        {defs.map((def) => (
          <OptimizationRow key={def.id} def={def} />
        ))}
      </div>
    </div>
  );
}

/** Auto-clean RAM when a game launches; result shows in the in-game overlay. */
function AutoRamCleanRow() {
  const config = useSettingsStore((s) => s.settings.config);
  const updateSettings = useSettingsStore((s) => s.update);
  const saveSettings = useSettingsStore((s) => s.save);
  const updateConfig = useBoostStore((s) => s.updateConfig);
  const [busy, setBusy] = useState(false);

  const enabled = config.system_optimization.auto_ram_clean;

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

  const grouped = TIER_ORDER.map((tier) => ({
    tier,
    defs: OPTIMIZATIONS.filter((d) => d.tier === tier),
  })).filter((g) => g.defs.length > 0);

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      <MemoryCleaner />
      <AutoRamCleanRow />

      {grouped.map((g) => (
        <OptimizationTierGroup key={g.tier} tier={g.tier} defs={g.defs} />
      ))}
    </div>
  );
}
