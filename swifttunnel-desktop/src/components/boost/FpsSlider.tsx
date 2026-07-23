import { useEffect, useState } from "react";
import { Slider } from "../ui";

/** Shared FPS target control used by the boost page and the Home dashboard, so
 *  the two stay visually and behaviourally identical. Slider range 30–1010; the
 *  last notch (1010) is the "uncapped" position (target_fps = 99999). */
export function FpsSlider({
  value,
  onChange,
  disabled,
}: {
  value: number;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const UNCAP_POS = 1010;
  const isUncapped = value >= 9999;
  const sliderValue = isUncapped
    ? UNCAP_POS
    : Math.max(30, Math.min(value, 1000));
  const [inputText, setInputText] = useState(isUncapped ? "" : String(value));
  const [inputFocused, setInputFocused] = useState(false);

  useEffect(() => {
    if (!inputFocused) {
      setInputText(isUncapped ? "" : String(value));
    }
  }, [value, isUncapped, inputFocused]);

  function commitInput(raw: string) {
    const v = Number.parseInt(raw, 10);
    if (!Number.isFinite(v) || v < 30) {
      setInputText(isUncapped ? "" : String(value));
      return;
    }
    onChange(Math.min(v, 99999));
  }

  function handleSlider(v: number) {
    if (v >= UNCAP_POS) onChange(99999);
    else onChange(Math.min(v, 1000));
  }

  return (
    <div className="px-4 py-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-baseline gap-2">
          <span className="text-[11px] text-text-muted">Target FPS</span>
          {isUncapped && (
            <span
              className="rounded-[3px] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.1em]"
              style={{
                backgroundColor: "var(--color-accent-primary-soft-15)",
                color: "var(--color-accent-secondary)",
              }}
            >
              Uncapped
            </span>
          )}
        </div>
        <input
          type="number"
          min={30}
          max={99999}
          value={inputText}
          placeholder="MAX"
          disabled={disabled}
          onFocus={() => setInputFocused(true)}
          onChange={(e) => {
            setInputText(e.target.value);
            const v = Number.parseInt(e.target.value, 10);
            if (Number.isFinite(v) && v >= 30 && v <= 99999) onChange(v);
          }}
          onBlur={(e) => {
            setInputFocused(false);
            commitInput(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
          }}
          className="boost-input w-[78px] rounded-[4px] px-2 py-1 text-right font-mono text-[12px] font-semibold outline-none transition-colors"
          style={{
            backgroundColor: "var(--color-bg-elevated)",
            border: "1px solid var(--color-border-default)",
            color: isUncapped
              ? "var(--color-accent-secondary)"
              : "var(--color-text-primary)",
          }}
        />
      </div>
      <Slider
        ariaLabel="Target FPS slider"
        min={30}
        max={UNCAP_POS}
        step={10}
        value={sliderValue}
        onChange={handleSlider}
        disabled={disabled}
      />
      <div className="mt-1.5 flex justify-between font-mono text-[9.5px] text-text-dimmed">
        <span>30</span>
        <span>120</span>
        <span>240</span>
        <span>360</span>
        <span
          style={{
            color:
              !isUncapped && value >= 1000
                ? "var(--color-text-primary)"
                : undefined,
          }}
        >
          1000
        </span>
        <span
          style={{
            color: isUncapped ? "var(--color-accent-secondary)" : undefined,
            fontWeight: isUncapped ? 700 : undefined,
          }}
        >
          MAX
        </span>
      </div>
    </div>
  );
}
