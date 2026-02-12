interface ToggleProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
}

export function Toggle({ enabled, onChange, disabled }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      onClick={() => !disabled && onChange(!enabled)}
      className={`relative h-[22px] w-[42px] shrink-0 rounded-full transition-colors duration-200 ${
        disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"
      }`}
      style={{
        backgroundColor: enabled
          ? "var(--color-accent-primary)"
          : "var(--color-bg-hover)",
      }}
    >
      <div
        className="absolute top-[3px] h-4 w-4 rounded-full bg-white shadow-sm transition-all duration-200"
        style={{ left: enabled ? "23px" : "3px" }}
      />
    </button>
  );
}
