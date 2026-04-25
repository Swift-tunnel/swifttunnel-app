import type { HTMLAttributes, ReactNode } from "react";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  padding?: "none" | "sm" | "md" | "lg";
  interactive?: boolean;
  selected?: boolean;
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
  as = "div",
  className,
  style,
  children,
  ...rest
}: CardProps) {
  const Tag = as as "div";
  return (
    <Tag
      className={`rounded-[var(--radius-card)] ${padClass[padding]} ${interactive ? "cursor-pointer transition-colors duration-100" : ""} ${className ?? ""}`}
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : "var(--color-bg-card)",
        border: `1px solid ${selected ? "var(--color-accent-primary)" : "var(--color-border-subtle)"}`,
        ...style,
      }}
      {...rest}
    >
      {children}
    </Tag>
  );
}
