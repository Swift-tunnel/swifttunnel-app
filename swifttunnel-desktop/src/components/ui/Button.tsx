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
  md: "h-[34px] px-3.5 text-[12px]",
  lg: "h-[42px] px-5 text-[13px]",
};

const baseClasses =
  "inline-flex select-none items-center justify-center gap-1.5 rounded-[var(--radius-button)] font-medium transition-all duration-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-[color:var(--color-accent-primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[color:var(--color-bg-base)] disabled:cursor-not-allowed disabled:opacity-50";

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
    const isPrimary = variant === "primary";
    const isConnect = variant === "connect";

    let variantStyle: React.CSSProperties = {};
    let variantClass = "";

    switch (variant) {
      case "primary":
        variantClass = "btn-primary-gloss";
        variantStyle = { color: "#0a0a0a" };
        break;
      case "secondary":
        variantStyle = {
          backgroundColor: "var(--color-bg-elevated)",
          color: "var(--color-text-primary)",
          border: "1px solid var(--color-border-default)",
        };
        break;
      case "ghost":
        variantStyle = {
          backgroundColor: "transparent",
          color: "var(--color-text-secondary)",
        };
        break;
      case "destructive":
        variantStyle = {
          backgroundColor: "transparent",
          color: "var(--color-status-error)",
          border: "1px solid var(--color-status-error-soft-20)",
        };
        break;
      case "connect":
        variantStyle = {
          background: "linear-gradient(180deg, #34d39a 0%, #1fbf86 100%)",
          color: "#04140e",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.25), 0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(0,0,0,0.5)",
        };
        break;
    }

    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={`${baseClasses} ${sizeClasses[size]} ${variantClass} ${fullWidth ? "w-full" : ""} ${className ?? ""}`}
        style={{ ...variantStyle, ...style }}
        {...rest}
      >
        {loading ? (
          <span
            className="inline-block h-3 w-3 animate-spin rounded-full border-[1.5px] border-current border-t-transparent"
            style={{ opacity: isPrimary || isConnect ? 0.7 : 0.8 }}
          />
        ) : (
          leadingIcon
        )}
        <span className="leading-none tracking-[-0.005em]">{children}</span>
        {!loading && trailingIcon}
      </button>
    );
  },
);
