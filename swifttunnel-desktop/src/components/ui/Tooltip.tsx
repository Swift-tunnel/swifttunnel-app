import {
  useState,
  useRef,
  useEffect,
  type ReactNode,
  type ReactElement,
  cloneElement,
} from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";

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
  /** When true the child renders normally but the tooltip never shows.
   *  Lets callers keep the Tooltip permanently mounted (avoiding a child
   *  remount) while suppressing the popup in states where it isn't wanted. */
  disabled?: boolean;
}

export function Tooltip({
  content,
  children,
  side = "top",
  delay = 350,
  disabled = false,
}: TooltipProps) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  useEffect(() => {
    if (disabled) hide();
  }, [disabled]);

  useEffect(() => {
    if (!open) return;
    // Its anchor may move without a pointer event. Dismiss rather than keep
    // a fixed popup floating over unrelated controls after scrolling.
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    window.addEventListener("blur", hide);
    return () => {
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
      window.removeEventListener("blur", hide);
    };
  }, [open]);

  function show(el: HTMLElement) {
    if (disabled) return;
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      timer.current = null;
      if (!el.isConnected) return;
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
    if (timer.current !== null) clearTimeout(timer.current);
    timer.current = null;
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
        !disabled &&
        createPortal(
          <div
            role="tooltip"
            className="pointer-events-none fixed z-[9999] max-w-[220px] rounded-[5px] px-2 py-1.5 text-[11px] leading-tight"
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
    <Icon
      name="info"
      size={12}
      strokeWidth={2}
      style={{ color: "var(--color-text-dimmed)" }}
    />
  );
}
