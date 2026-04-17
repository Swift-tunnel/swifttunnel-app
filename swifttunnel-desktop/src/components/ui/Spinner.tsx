interface SpinnerProps {
  size?: number;
  color?: string;
  thickness?: number;
  className?: string;
}

export function Spinner({
  size = 14,
  color = "currentColor",
  thickness = 1.5,
  className,
}: SpinnerProps) {
  return (
    <span
      className={`inline-block shrink-0 animate-spin rounded-full border-current border-t-transparent ${className ?? ""}`}
      style={{
        width: size,
        height: size,
        borderWidth: thickness,
        color,
      }}
      aria-hidden
    />
  );
}
