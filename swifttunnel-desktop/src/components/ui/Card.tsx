import type { HTMLAttributes, ReactNode } from "react";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  padding?: "none" | "sm" | "md" | "lg";
  interactive?: boolean;
  selected?: boolean;
  variant?: "default" | "elevated";
  as?: "div" | "section" | "article";
  children: ReactNode;
}

const padClass = {
  none: "",
  sm: "p-3",
  md: "p-4",
  lg: "p-5",
} as const;

export function Card({
  padding = "md",
  interactive,
  selected,
  variant = "default",
  as = "div",
  className,
  style,
  children,
  ...rest
}: CardProps) {
  const Tag = as as "div";
  const surfaceClass =
    variant === "elevated" ? "surface-elevated" : "surface-card";

  return (
    <Tag
      className={`rounded-[var(--radius-card)] ${surfaceClass} ${padClass[padding]} ${interactive ? "cursor-pointer transition-colors duration-100" : ""} ${className ?? ""}`}
      style={
        selected
          ? {
              backgroundColor: "var(--color-accent-primary-soft-8)",
              borderColor: "var(--color-accent-primary)",
              ...style,
            }
          : style
      }
      {...rest}
    >
      {children}
    </Tag>
  );
}
