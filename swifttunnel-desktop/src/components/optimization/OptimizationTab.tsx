import { useEffect, type ReactNode } from "react";
import {
  SectionHeader,
  Row,
  Toggle,
  Tooltip,
  InfoIcon,
  Spinner,
} from "../ui";
import { MemoryCleaner } from "../boost/MemoryCleaner";
import { useOptimizationStore } from "../../stores/optimizationStore";
import {
  OPTIMIZATIONS,
  CATEGORY_ORDER,
  type OptimizationDef,
  type OptCategory,
} from "./optimizationCatalog";

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
        <Tooltip content={changesTooltip(def)}>
          <span className="inline-flex">
            <InfoIcon />
          </span>
        </Tooltip>
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

function OptimizationGroup({
  category,
  defs,
}: {
  category: OptCategory;
  defs: OptimizationDef[];
}) {
  const statuses = useOptimizationStore((s) => s.status);
  const activeCount = defs.filter((d) => statuses[d.id] === "active").length;

  return (
    <section>
      <SectionHeader label={category} tag={`${activeCount} / ${defs.length} on`} />
      <div className="overflow-hidden rounded-[var(--radius-card)] surface-card divide-y divide-[color:var(--color-border-subtle)]">
        {defs.map((def) => (
          <OptimizationRow key={def.id} def={def} />
        ))}
      </div>
    </section>
  );
}

export function OptimizationTab() {
  const loadActive = useOptimizationStore((s) => s.loadActive);

  // Reflect which optimizations are already applied (persisted on disk).
  useEffect(() => {
    void loadActive();
  }, [loadActive]);

  const grouped = CATEGORY_ORDER.map((category) => ({
    category,
    defs: OPTIMIZATIONS.filter((d) => d.category === category),
  })).filter((g) => g.defs.length > 0);

  return (
    <div className="flex w-full flex-col gap-4 pb-24">
      <div className="mb-1">
        <span className="eyebrow">Optimization</span>
        <h2 className="mt-3 text-[22px] font-semibold leading-none text-text-primary">
          Optimize
        </h2>
        <p className="mt-2 text-[12.5px] text-text-muted">
          Reversible Windows tweaks for FPS and latency. Toggle any off to
          restore your previous settings.
        </p>
      </div>

      <MemoryCleaner />

      {grouped.map((g) => (
        <OptimizationGroup
          key={g.category}
          category={g.category}
          defs={g.defs}
        />
      ))}
    </div>
  );
}
