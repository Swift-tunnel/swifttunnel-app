import {
  useState,
  useRef,
  useEffect,
  type ReactNode,
  type ReactElement,
  cloneElement,
} from "react";
import { createPortal } from "react-dom";

interface TooltipProps {
  content: ReactNode;
  children: ReactElement<{
    onMouseEnter?: (e: React.MouseEvent) => void;
    onMouseLeave?: (e: React.MouseEvent) => void;
    onFocus?: (e: React.FocusEvent) => void;
    onBlur?: (e: React.FocusEvent) => void;
  }>;
  side?: "top" | "bottom" | "left" | "right";
  delay?: number;
}

export function Tooltip({
  content,
  children,
  side = "top",
  delay = 350,
}: TooltipProps) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const anchorRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  function show(el: HTMLElement) {
    anchorRef.current = el;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const r = el.getBoundingClientRect();
      let x = r.left + r.width / 2;
      let y = r.top + r.height / 2;
      if (side === "top") y = r.top;
      else if (side === "bottom") y = r.bottom;
      else if (side === "left") x = r.left;
      else if (side === "right") x = r.right;
      setPos({ x, y });
      setOpen(true);
    }, delay);
  }

  function hide() {
    if (timer.current) clearTimeout(timer.current);
    setOpen(false);
    setPos(null);
  }

  const enhanced = cloneElement(children, {
    onMouseEnter: (e: React.MouseEvent) => {
      show(e.currentTarget as HTMLElement);
      children.props.onMouseEnter?.(e);
    },
    onMouseLeave: (e: React.MouseEvent) => {
      hide();
      children.props.onMouseLeave?.(e);
    },
    onFocus: (e: React.FocusEvent) => {
      show(e.currentTarget as HTMLElement);
      children.props.onFocus?.(e);
    },
    onBlur: (e: React.FocusEvent) => {
      hide();
      children.props.onBlur?.(e);
    },
  });

  return (
    <>
      {enhanced}
      {open &&
        pos &&
        createPortal(
          <div
            role="tooltip"
            className="pointer-events-none fixed z-[9999] max-w-[220px] rounded-[5px] px-2 py-1.5 text-[11px] leading-tight shadow-lg"
            style={{
              left: pos.x,
              top: pos.y,
              transform:
                side === "top"
                  ? "translate(-50%, calc(-100% - 6px))"
                  : side === "bottom"
                    ? "translate(-50%, 6px)"
                    : side === "left"
                      ? "translate(calc(-100% - 6px), -50%)"
                      : "translate(6px, -50%)",
              backgroundColor: "var(--color-bg-elevated)",
              color: "var(--color-text-primary)",
              border: "1px solid var(--color-border-default)",
            }}
          >
            {content}
          </div>,
          document.body,
        )}
    </>
  );
}

export function InfoIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      style={{ color: "var(--color-text-dimmed)" }}
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}
