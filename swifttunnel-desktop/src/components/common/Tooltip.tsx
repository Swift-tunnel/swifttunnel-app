import { useState, useRef, useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";

export function Tooltip({
  content,
  children,
}: {
  content: string;
  children: ReactNode;
}) {
  const [visible, setVisible] = useState(false);
  const [pos, setPos] = useState({ x: 0, y: 0, flip: false });
  const triggerRef = useRef<HTMLSpanElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function show() {
    timerRef.current = setTimeout(() => {
      if (!triggerRef.current) return;
      const rect = triggerRef.current.getBoundingClientRect();
      const flip = rect.top < 60;
      setPos({
        x: rect.left + rect.width / 2,
        y: flip ? rect.bottom + 6 : rect.top - 6,
        flip,
      });
      setVisible(true);
    }, 300);
  }

  function hide() {
    if (timerRef.current) clearTimeout(timerRef.current);
    setVisible(false);
  }

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return (
    <>
      <span
        ref={triggerRef}
        onMouseEnter={show}
        onMouseLeave={hide}
        className="inline-flex cursor-help"
      >
        {children}
      </span>
      {createPortal(
        <AnimatePresence>
          {visible && (
            <motion.div
              initial={{ opacity: 0, y: pos.flip ? -4 : 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: pos.flip ? -4 : 4 }}
              transition={{ duration: 0.15 }}
              className="pointer-events-none fixed z-[9999] max-w-[240px] rounded-[var(--radius-sm)] border border-border-subtle px-3 py-2 text-[11px] leading-relaxed text-text-secondary shadow-lg"
              style={{
                left: pos.x,
                top: pos.y,
                transform: pos.flip
                  ? "translateX(-50%)"
                  : "translateX(-50%) translateY(-100%)",
                backgroundColor: "var(--color-bg-elevated)",
              }}
            >
              {content}
            </motion.div>
          )}
        </AnimatePresence>,
        document.body,
      )}
    </>
  );
}

export function InfoIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--color-text-dimmed)"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}
