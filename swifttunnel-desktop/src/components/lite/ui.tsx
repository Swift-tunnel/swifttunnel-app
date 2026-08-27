import type { ReactNode } from "react";

/**
 * Lite's own controls.
 *
 * Deliberately not the full app's. Those are drawn for a 1020px window: cards
 * with 18px corners, 56px rows, a gradient sheen and a shadow, spaced 10px
 * apart on a washed background. Shrinking them produced exactly what it sounds
 * like, a miniature of a big app, which is the thing this build kept being
 * accused of being.
 *
 * The grammar here is a settings flyout instead: flat groups of dense rows
 * separated by hairlines, a small uppercase caption over each group, and one
 * primary button. Same palette, same typeface, same product. Different object.
 */

const CAPTION =
  "px-1 pb-1.5 text-[9.5px] font-semibold uppercase tracking-[0.09em]";

/** A captioned block of rows. */
export function Group({
  title,
  children,
  action,
}: {
  title?: string;
  children: ReactNode;
  /** Small right-aligned control in the caption line, e.g. a "Refresh". */
  action?: ReactNode;
}) {
  return (
    <section className="mb-3.5">
      {title && (
        <div className="flex items-end justify-between">
          <div className={CAPTION} style={{ color: "var(--color-text-dimmed)" }}>
            {title}
          </div>
          {action}
        </div>
      )}
      <div
        className="overflow-hidden rounded-[8px]"
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

/**
 * One line in a group.
 *
 * 38px, which is the smallest a row can be and still take a comfortable click.
 * The separator is drawn on the row rather than between them so the last one
 * does not need a special case.
 */
export function Row({
  label,
  sub,
  right,
  onClick,
  disabled,
  first,
  tone,
}: {
  label: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  /** Suppresses the top hairline for the first row in a group. */
  first?: boolean;
  tone?: "danger";
}) {
  const body = (
    <>
      <div className="min-w-0 flex-1 text-left">
        <div
          className="truncate text-[12px] font-medium leading-tight"
          style={{
            color:
              tone === "danger"
                ? "var(--color-status-error)"
                : "var(--color-text-primary)",
          }}
        >
          {label}
        </div>
        {sub && (
          <div
            className="truncate text-[10px] leading-tight"
            style={{ color: "var(--color-text-dimmed)", marginTop: 1.5 }}
          >
            {sub}
          </div>
        )}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </>
  );

  const style = {
    minHeight: 38,
    borderTop: first ? "none" : "1px solid var(--color-border-subtle)",
    opacity: disabled ? 0.45 : 1,
  };

  if (!onClick) {
    return (
      <div className="flex items-center gap-2.5 px-2.5 py-1.5" style={style}>
        {body}
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex w-full items-center gap-2.5 px-2.5 py-1.5 text-left hover:bg-[color:var(--color-bg-hover)]"
      style={style}
    >
      {body}
    </button>
  );
}

/**
 * A 30x17 toggle.
 *
 * The app's is 44x24 with a spring animation on the knob. This one is sized
 * for a 38px row and moves by a plain 120ms transform, which the compositor
 * handles without keeping an animation alive.
 */
export function Switch({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="relative shrink-0 rounded-full"
      style={{
        width: 30,
        height: 17,
        backgroundColor: checked
          ? "var(--color-status-connected)"
          : "var(--color-bg-active)",
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "background-color 120ms linear",
      }}
    >
      <span
        className="absolute rounded-full"
        style={{
          width: 13,
          height: 13,
          top: 2,
          left: 2,
          backgroundColor: checked ? "#0a0a0a" : "var(--color-text-secondary)",
          transform: checked ? "translateX(13px)" : "none",
          transition: "transform 120ms linear",
        }}
      />
    </button>
  );
}

/** Inline choice chips, for the two or three option settings. */
export function Choice<T extends string | number>({
  value,
  options,
  onChange,
  disabled,
}: {
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (next: T) => void;
  disabled?: boolean;
}) {
  return (
    <div
      className="flex shrink-0 items-center gap-px rounded-[6px] p-px"
      style={{ backgroundColor: "var(--color-bg-base)" }}
    >
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={String(option.value)}
            type="button"
            disabled={disabled}
            onClick={() => onChange(option.value)}
            className="rounded-[5px] px-2 py-[3px] text-[10.5px] font-medium"
            style={{
              backgroundColor: active ? "var(--color-bg-hover)" : "transparent",
              color: active
                ? "var(--color-text-primary)"
                : "var(--color-text-dimmed)",
            }}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

/** The one full-width action on a screen. */
export function PrimaryButton({
  children,
  onClick,
  disabled,
  variant = "solid",
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  variant?: "solid" | "outline";
}) {
  const solid = variant === "solid";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="w-full rounded-[8px] text-[12.5px] font-semibold"
      style={{
        height: 38,
        backgroundColor: solid ? "var(--color-text-primary)" : "transparent",
        color: solid ? "#0a0a0a" : "var(--color-text-primary)",
        border: solid ? "none" : "1px solid var(--color-border-default)",
        opacity: disabled ? 0.4 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "opacity 120ms linear",
      }}
    >
      {children}
    </button>
  );
}

/** Right-hand value text on a read-only row. */
export function Value({
  children,
  color,
}: {
  children: ReactNode;
  color?: string;
}) {
  return (
    <span
      className="text-[11px] font-medium tabular-nums"
      style={{ color: color || "var(--color-text-secondary)" }}
    >
      {children}
    </span>
  );
}

export function Chevron() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-text-dimmed)"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="m9 18 6-6-6-6" />
    </svg>
  );
}
