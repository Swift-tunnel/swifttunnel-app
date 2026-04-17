import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "destructive" | "connect";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  fullWidth?: boolean;
}

const sizeClasses: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[11px]",
  md: "h-8 px-3 text-[12px]",
  lg: "h-11 px-5 text-[13px]",
};

const baseClasses =
  "inline-flex select-none items-center justify-center gap-1.5 rounded-[var(--radius-button)] font-medium transition-colors duration-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-base)] disabled:cursor-not-allowed disabled:opacity-50";

function variantStyle(variant: Variant): React.CSSProperties {
  switch (variant) {
    case "primary":
      return {
        backgroundColor: "var(--color-accent-primary)",
        color: "#fff",
      };
    case "secondary":
      return {
        backgroundColor: "var(--color-bg-elevated)",
        color: "var(--color-text-primary)",
        border: "1px solid var(--color-border-default)",
      };
    case "ghost":
      return {
        backgroundColor: "transparent",
        color: "var(--color-text-secondary)",
      };
    case "destructive":
      return {
        backgroundColor: "var(--color-status-error)",
        color: "#fff",
      };
    case "connect":
      return {
        backgroundColor: "var(--color-status-connected)",
        color: "#04140e",
      };
  }
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(
    {
      variant = "primary",
      size = "md",
      loading = false,
      leadingIcon,
      trailingIcon,
      fullWidth,
      className,
      children,
      disabled,
      style,
      ...rest
    },
    ref,
  ) {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={`${baseClasses} ${sizeClasses[size]} ${fullWidth ? "w-full" : ""} ${className ?? ""}`}
        style={{ ...variantStyle(variant), ...style }}
        {...rest}
      >
        {loading ? (
          <span className="inline-block h-3 w-3 animate-spin rounded-full border-[1.5px] border-current border-t-transparent" />
        ) : (
          leadingIcon
        )}
        <span className="leading-none tracking-[-0.005em]">{children}</span>
        {!loading && trailingIcon}
      </button>
    );
  },
);
