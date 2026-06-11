import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { PhysicalPosition } from "@tauri-apps/api/dpi";
import { currentMonitor, getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";

/** Payload emitted by the main window after an auto RAM clean. */
interface RamOverlayPayload {
  freedMb: number;
}

export const RAM_OVERLAY_EVENT = "ram-overlay-show";

const VISIBLE_MS = 4200;

function formatFreed(mb: number): { value: string; unit: string } {
  const m = Math.max(0, Math.round(mb));
  if (m >= 1024) return { value: (m / 1024).toFixed(2), unit: "GB" };
  return { value: String(m), unit: "MB" };
}

/**
 * The in-game "RAM freed" toast. Lives in its own transparent, always-on-top,
 * click-through window (label "overlay"). It positions itself at the top-right
 * of the active monitor, shows the window when the main window emits
 * RAM_OVERLAY_EVENT, animates the freed amount, then hides itself.
 */
export function RamOverlay() {
  const [freedMb, setFreedMb] = useState<number | null>(null);
  const [display, setDisplay] = useState(0);
  const hideTimer = useRef<number | null>(null);

  // One-time window setup: make it click-through so it never eats game input.
  useEffect(() => {
    const win = getCurrentWindow();
    void win.setIgnoreCursorEvents(true);
  }, []);

  // Show + position on demand.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;

    const positionTopRight = async () => {
      try {
        const win = getCurrentWindow();
        const monitor = await currentMonitor();
        if (!monitor) return;
        const size = await win.outerSize();
        const margin = Math.round(24 * monitor.scaleFactor);
        const x = monitor.position.x + monitor.size.width - size.width - margin;
        const y = monitor.position.y + margin;
        await win.setPosition(new PhysicalPosition(Math.round(x), Math.round(y)));
      } catch {
        /* positioning is best-effort */
      }
    };

    void listen<RamOverlayPayload>(RAM_OVERLAY_EVENT, async (event) => {
      if (disposed) return;
      const mb = event.payload?.freedMb ?? 0;
      await positionTopRight();
      const win = getCurrentWindow();
      try {
        await win.show();
      } catch {
        /* ignore */
      }
      setFreedMb(mb);

      if (hideTimer.current !== null) window.clearTimeout(hideTimer.current);
      hideTimer.current = window.setTimeout(() => {
        setFreedMb(null);
        // Let the exit animation play before hiding the OS window.
        window.setTimeout(() => void getCurrentWindow().hide(), 450);
      }, VISIBLE_MS);
    }).then((u) => {
      if (disposed) u();
      else unlisten = u;
    });

    return () => {
      disposed = true;
      if (hideTimer.current !== null) window.clearTimeout(hideTimer.current);
      unlisten?.();
    };
  }, []);

  // Count-up the number when a new value arrives.
  useEffect(() => {
    if (freedMb === null) return;
    const target = Math.max(0, freedMb);
    const start = performance.now();
    const dur = 1100;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(target * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [freedMb]);

  const shown = freedMb !== null;
  const { value, unit } = formatFreed(display);
  const nothing = freedMb !== null && Math.max(0, freedMb) < 40;

  return (
    <div className="h-screen w-screen overflow-hidden bg-transparent">
      <style>{ringKeyframes}</style>
      <AnimatePresence>
        {shown && (
          <motion.div
            key="ram-toast"
            initial={{ opacity: 0, x: 40, scale: 0.92 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 24, scale: 0.96 }}
            transition={{ type: "spring", stiffness: 420, damping: 30 }}
            className="flex items-center gap-3 rounded-2xl px-4 py-3"
            style={{
              margin: 6,
              background:
                "linear-gradient(135deg, rgba(14,18,30,0.94), rgba(9,12,20,0.94))",
              border: "1px solid rgba(70,140,255,0.35)",
              boxShadow:
                "0 8px 30px rgba(0,0,0,0.5), 0 0 0 1px rgba(70,140,255,0.10), 0 0 28px rgba(60,130,255,0.28)",
              backdropFilter: "blur(10px)",
            }}
          >
            {/* Animated emblem */}
            <div className="relative flex h-11 w-11 shrink-0 items-center justify-center">
              <span style={ringStyle(0)} />
              <span style={ringStyle(0.6)} />
              <motion.div
                initial={{ rotate: -25, scale: 0.7 }}
                animate={{ rotate: 0, scale: 1 }}
                transition={{ type: "spring", stiffness: 300, damping: 18 }}
                className="relative flex h-9 w-9 items-center justify-center rounded-xl"
                style={{
                  background:
                    "radial-gradient(circle at 30% 25%, rgba(90,160,255,0.9), rgba(40,90,210,0.85))",
                  boxShadow: "0 0 16px rgba(70,140,255,0.6)",
                }}
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                  <rect
                    x="3.5"
                    y="6.5"
                    width="17"
                    height="11"
                    rx="2"
                    stroke="white"
                    strokeWidth="1.6"
                  />
                  <path
                    d="M7 6.5V4M12 6.5V4M17 6.5V4M7 20v-2.5M12 20v-2.5M17 20v-2.5"
                    stroke="white"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                  />
                </svg>
              </motion.div>
            </div>

            {/* Text */}
            <div className="flex min-w-0 flex-col">
              <span
                className="text-[10px] font-semibold uppercase tracking-[0.12em]"
                style={{ color: "rgba(150,185,255,0.9)" }}
              >
                {nothing ? "Memory Optimized" : "RAM Freed"}
              </span>
              {!nothing && (
                <span className="flex items-baseline gap-1 leading-none">
                  <span
                    className="text-[24px] font-bold tabular-nums"
                    style={{
                      color: "#eaf1ff",
                      textShadow: "0 0 18px rgba(80,150,255,0.55)",
                    }}
                  >
                    {value}
                  </span>
                  <span
                    className="text-[12px] font-semibold"
                    style={{ color: "rgba(150,185,255,0.95)" }}
                  >
                    {unit}
                  </span>
                </span>
              )}
              <span
                className="mt-0.5 text-[10.5px]"
                style={{ color: "rgba(160,175,205,0.75)" }}
              >
                {nothing ? "System memory trimmed" : "released by SwiftTunnel"}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ringStyle(delay: number): React.CSSProperties {
  return {
    position: "absolute",
    inset: 0,
    borderRadius: 14,
    border: "1.5px solid rgba(90,160,255,0.55)",
    animation: `swiftRamRing 1.8s ease-out ${delay}s infinite`,
  };
}

const ringKeyframes = `
@keyframes swiftRamRing {
  0% { transform: scale(0.7); opacity: 0.7; }
  70% { opacity: 0; }
  100% { transform: scale(1.8); opacity: 0; }
}`;
