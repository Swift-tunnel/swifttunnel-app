import { useEffect, useState, type ReactNode, type SelectHTMLAttributes } from "react";
import { Icon } from "./Icon";
import { Slider } from "./Slider";

/** Text boxes in a dialog form, matching the preset dialogs. */
export const fieldClass =
  "h-9 w-full rounded-[9px] border border-border-subtle bg-bg-base px-3 text-[12.5px] text-text-primary outline-none transition-colors placeholder:text-text-dimmed focus-visible:border-border-focus disabled:cursor-not-allowed disabled:opacity-50";

/** Small boxes that sit on a card: search, a flag's value, a frame limit. */
export const compactFieldClass =
  "h-[30px] rounded-[var(--radius-input)] border border-border-default bg-bg-elevated px-2.5 text-[11.5px] text-text-primary outline-none transition-colors placeholder:text-text-dimmed focus-visible:border-border-focus disabled:cursor-not-allowed disabled:opacity-50";

interface FieldProps {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}

/** A labelled control in a dialog form. */
export function Field({ label, hint, children, className }: FieldProps) {
  return (
    <label className={`flex min-w-0 flex-col gap-1.5 ${className ?? ""}`}>
      <span className="text-[11px] font-medium text-text-secondary">{label}</span>
      {children}
      {hint && (
        <span className="text-[11px] leading-snug text-text-muted">{hint}</span>
      )}
    </label>
  );
}

/**
 * The width of a control in a row's right-hand column. Dropdowns, switches and
 * sliders all take it, so a list of settings lines up on both edges.
 */
export const CONTROL_WIDTH = 288;

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  /** Fill the form's width. Without it every dropdown is CONTROL_WIDTH wide. */
  block?: boolean;
  width?: number;
}

/**
 * The native dropdown, so the keyboard and screen readers work as usual,
 * wearing the app's own face instead of the browser's.
 */
export function Select({ block, width = CONTROL_WIDTH, className, children, ...rest }: SelectProps) {
  return (
    <span
      className={`relative inline-flex ${block ? "w-full" : ""} ${className ?? ""}`}
      style={block ? undefined : { width }}
    >
      <select
        {...rest}
        className={`w-full cursor-pointer appearance-none truncate pr-8 [color-scheme:dark] ${
          block ? fieldClass : `${compactFieldClass} font-medium`
        }`}
      >
        {children}
      </select>
      <Icon
        name="chevron-down"
        size={12}
        strokeWidth={2.2}
        className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted"
      />
    </span>
  );
}

interface SliderInputProps {
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (value: number) => void;
  disabled?: boolean;
  ariaLabel: string;
  unit?: string;
  /** Width of the whole control. The track takes whatever the box leaves. */
  width?: number;
}

/**
 * A slider with a box you can type into. The slider moves in steps; a typed
 * number can be anything in range, and is applied on Enter or when you leave
 * the box.
 */
export function SliderInput({
  value,
  min,
  max,
  step = 1,
  onChange,
  disabled,
  ariaLabel,
  unit,
  width = CONTROL_WIDTH,
}: SliderInputProps) {
  const [text, setText] = useState(String(value));
  const [typing, setTyping] = useState(false);
  useEffect(() => {
    if (!typing) setText(String(value));
  }, [value, typing]);

  function commit() {
    setTyping(false);
    const typed = Number.parseInt(text, 10);
    if (Number.isFinite(typed)) onChange(Math.max(min, Math.min(max, typed)));
  }

  return (
    <div className="flex shrink-0 items-center gap-3" style={{ width }}>
      <div className="flex min-w-0 flex-1 items-center">
        <Slider
          ariaLabel={`${ariaLabel} slider`}
          value={Math.max(min, Math.min(max, value))}
          min={min}
          max={max}
          step={step}
          onChange={onChange}
          disabled={disabled}
          trackColor="var(--color-bg-active)"
        />
      </div>
      {/* The unit sits inside the box, so boxes with and without one end on the same edge. */}
      <label
        className={`flex h-[30px] shrink-0 cursor-text items-center gap-1.5 rounded-[var(--radius-input)] border border-border-default bg-bg-elevated px-2.5 transition-colors focus-within:border-border-focus ${disabled ? "opacity-50" : ""}`}
      >
        <input
          aria-label={ariaLabel}
          inputMode="numeric"
          value={text}
          disabled={disabled}
          onFocus={() => setTyping(true)}
          onChange={(e) => setText(e.target.value.replace(/\D/g, ""))}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          className="w-[38px] bg-transparent text-right font-mono text-[11.5px] font-semibold text-text-primary outline-none disabled:cursor-not-allowed"
        />
        {unit && (
          <span className="font-mono text-[10px] text-text-dimmed">{unit}</span>
        )}
      </label>
    </div>
  );
}
