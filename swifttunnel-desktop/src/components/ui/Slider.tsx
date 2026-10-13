interface SliderProps {
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (v: number) => void;
  disabled?: boolean;
  ariaLabel?: string;
  className?: string;
  /** Colour of the unfilled part. The default disappears on a dialog, which is the same grey. */
  trackColor?: string;
}

export function Slider({
  value,
  min,
  max,
  step = 1,
  onChange,
  disabled,
  ariaLabel,
  className,
  trackColor = "var(--color-bg-elevated)",
}: SliderProps) {
  const pct = Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100));
  return (
    <input
      type="range"
      aria-label={ariaLabel}
      min={min}
      max={max}
      step={step}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(Number(e.target.value))}
      className={`ui-slider w-full ${className ?? ""}`}
      style={{
        background: disabled
          ? trackColor
          : `linear-gradient(to right, var(--color-accent-primary) 0%, var(--color-accent-primary) ${pct}%, ${trackColor} ${pct}%, ${trackColor} 100%)`,
      }}
    />
  );
}
