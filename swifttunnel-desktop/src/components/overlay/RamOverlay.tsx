import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { PhysicalPosition } from "@tauri-apps/api/dpi";
import {
  currentMonitor,
  getAllWindows,
  getCurrentWindow,
} from "@tauri-apps/api/window";
import { emitTo, listen } from "@tauri-apps/api/event";

/** Payload emitted by the main window after an auto RAM clean. */
interface RamOverlayPayload {
  freedMb: number;
}

export const RAM_OVERLAY_EVENT = "ram-overlay-show";

const VISIBLE_MS = 5500;

/**
 * Show the overlay toast from the main window: reveal the (hidden) overlay
 * window and emit the freed amount to it. Throws a clear error if the overlay
 * window doesn't exist (e.g. SwiftTunnel wasn't fully restarted after the
 * config that adds it), so callers can surface that instead of failing silently.
 */
export async function showRamOverlay(freedMb: number): Promise<void> {
  const overlay = (await getAllWindows()).find((w) => w.label === "overlay");
  if (!overlay) {
    throw new Error(
      "Overlay window not found - fully quit and reopen SwiftTunnel so the new overlay window loads.",
    );
  }
  await overlay.show();
  await emitTo("overlay", RAM_OVERLAY_EVENT, { freedMb });
}

function formatFreed(mb: number): { value: string; unit: string } {
  const m = Math.max(0, mb);
  if (m >= 1024) return { value: (m / 1024).toFixed(2), unit: "GB" };
  return { value: String(Math.round(m)), unit: "MB" };
}

/**
 * The in-game "RAM freed" toast. Lives in its own transparent, always-on-top,
 * click-through window (label "overlay"); it matches the SwiftTunnel look
 * (monochrome, surface-card). Positions itself at the top-right of the active
 * monitor, shows on RAM_OVERLAY_EVENT, animates the freed amount, then hides.
 */
export function RamOverlay() {
  const [freedMb, setFreedMb] = useState<number | null>(null);
  const [display, setDisplay] = useState(0);
  const hideTimer = useRef<number | null>(null);

  useEffect(() => {
    void getCurrentWindow().setIgnoreCursorEvents(true);
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;

    const positionTopRight = async () => {
      try {
        const win = getCurrentWindow();
        const monitor = await currentMonitor();
        if (!monitor) return;
        const size = await win.outerSize();
        const margin = Math.round(28 * monitor.scaleFactor);
        const x = monitor.position.x + monitor.size.width - size.width - margin;
        const y = monitor.position.y + margin;
        await win.setPosition(new PhysicalPosition(Math.round(x), Math.round(y)));
      } catch {
        /* best-effort */
      }
    };

    void listen<RamOverlayPayload>(RAM_OVERLAY_EVENT, async (event) => {
      if (disposed) return;
      const mb = event.payload?.freedMb ?? 0;
      await positionTopRight();
      try {
        await getCurrentWindow().show();
      } catch {
        /* ignore */
      }
      setFreedMb(mb);
      if (hideTimer.current !== null) window.clearTimeout(hideTimer.current);
      hideTimer.current = window.setTimeout(() => {
        setFreedMb(null);
        window.setTimeout(() => void getCurrentWindow().hide(), 520);
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

  // Count-up when a value arrives.
  useEffect(() => {
    if (freedMb === null) return;
    const target = Math.max(0, freedMb);
    const start = performance.now();
    const dur = 1400;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setDisplay(target * eased);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [freedMb]);

  const shown = freedMb !== null;
  const nothing = freedMb !== null && Math.max(0, freedMb) < 40;
  const { value, unit } = formatFreed(display);

  return (
    <div className="h-screen w-screen overflow-hidden bg-transparent">
      <style>{keyframes}</style>
      <AnimatePresence>
        {shown && (
          <motion.div
            key="ram-toast"
            initial={{ opacity: 0, x: 36, scale: 0.96 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 20, scale: 0.97 }}
            transition={{ type: "spring", stiffness: 360, damping: 32 }}
            className="relative flex items-center gap-3 overflow-hidden"
            style={{
              margin: 8,
              padding: "12px 16px 12px 13px",
              borderRadius: "var(--radius-card)",
              background: "rgba(20,20,20,0.96)",
              border: "1px solid rgba(255,255,255,0.10)",
              boxShadow:
                "0 10px 34px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.04), 0 0 24px rgba(255,255,255,0.05)",
              backdropFilter: "blur(12px)",
            }}
          >
            {/* one-shot shimmer sweep */}
            <span className="ram-shimmer" />

            {/* Emblem */}
            <div className="relative flex h-10 w-10 shrink-0 items-center justify-center">
              <span style={ringStyle} />
              <motion.div
                initial={{ scale: 0.7, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring", stiffness: 320, damping: 18 }}
                className="relative flex h-9 w-9 items-center justify-center"
                style={{
                  borderRadius: 10,
                  background: "rgba(255,255,255,0.07)",
                  border: "1px solid rgba(255,255,255,0.12)",
                }}
              >
                <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
                  <rect
                    x="3.5"
                    y="6.5"
                    width="17"
                    height="11"
                    rx="2"
                    stroke="#f5f5f5"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M7 6.5V4M12 6.5V4M17 6.5V4M7 20v-2.5M12 20v-2.5M17 20v-2.5"
                    stroke="#f5f5f5"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
              </motion.div>
            </div>

            {/* Text */}
            <div className="flex min-w-0 flex-col">
              <span
                className="text-[9.5px] font-semibold uppercase tracking-[0.13em]"
                style={{ color: "var(--color-text-muted)" }}
              >
                {nothing ? "Memory Optimized" : "RAM Freed"}
              </span>
              {!nothing && (
                <span className="mt-0.5 flex items-baseline gap-1 leading-none">
                  <span
                    className="text-[23px] font-bold tabular-nums"
                    style={{ color: "var(--color-text-primary)" }}
                  >
                    {value}
                  </span>
                  <span
                    className="text-[12px] font-semibold"
                    style={{ color: "var(--color-text-muted)" }}
                  >
                    {unit}
                  </span>
                </span>
              )}
              <span
                className="mt-0.5 text-[10px]"
                style={{ color: "rgba(255,255,255,0.32)" }}
              >
                SwiftTunnel
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

const ringStyle: React.CSSProperties = {
  position: "absolute",
  inset: 0,
  borderRadius: 12,
  border: "1.5px solid rgba(255,255,255,0.35)",
  animation: "swiftRamRing 2s ease-out 0.15s 2",
};

const keyframes = `
@keyframes swiftRamRing {
  0% { transform: scale(0.7); opacity: 0.55; }
  70% { opacity: 0; }
  100% { transform: scale(1.75); opacity: 0; }
}
.ram-shimmer {
  position: absolute;
  top: 0; bottom: 0; left: -40%;
  width: 35%;
  background: linear-gradient(100deg, transparent, rgba(255,255,255,0.10), transparent);
  transform: skewX(-18deg);
  animation: swiftRamShimmer 1.5s ease-out 0.25s 1;
  pointer-events: none;
}
@keyframes swiftRamShimmer {
  0% { left: -40%; opacity: 0; }
  25% { opacity: 1; }
  100% { left: 130%; opacity: 0; }
}`;
