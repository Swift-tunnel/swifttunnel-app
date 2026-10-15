import { useCallback, useEffect, useRef, useState } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import { currentMonitor, getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { OverlayBar } from "./OverlayBar";
import {
  OVERLAY_RENDER_EVENT,
  emitOverlayPosition,
  overlayMayInteract,
  overlayShouldShow,
  type OverlayRenderPayload,
} from "./overlayBus";
import { boostCursorPos } from "../../lib/commands";
import {
  clampOverlayPosition,
  overlayAnchor,
  overlayHeartbeatExpired,
  validOverlayMonitor,
  type OverlayMonitor,
} from "./overlayGeometry";

const IDLE_POLL_MS = 350;
const HIDDEN_POLL_MS = 1000;
const DRAG_POLL_MS = 16; // smooth window-follow while dragging
// Slack (CSS px) around the bar so it's easy to land the cursor on it to grab.
const GRAB_PAD = 8;
/** CSS px from the monitor edge for the 3x3 anchor presets. */
/** After a drop, ignore payloads still carrying the pre-save position. */
const DROP_GRACE_MS = 2500;

/**
 * The stats-overlay window root. The window is sized to the BAR itself (not
 * fullscreen), this is load-bearing: a fullscreen window that ever becomes
 * interactive captures every click on the desktop, and one stuck flag froze
 * the user's whole PC. A bar-sized window can't do that by construction.
 *
 * Dragging moves the WINDOW, driven entirely by polling the OS cursor +
 * left-button state (`boost_cursor_pos`), never webview mouse events, which
 * are unreliable on a click-through window whose interactivity flips mid-drag.
 */
export function OverlayStatsBar() {
  const [payload, setPayload] = useState<OverlayRenderPayload | null>(null);
  const [active, setActive] = useState(false); // hovered or dragging

  const payloadRef = useRef<OverlayRenderPayload | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const barRef = useRef<HTMLDivElement | null>(null);
  const monitorRef = useRef<OverlayMonitor | null>(null);
  const lastRenderRef = useRef<number | null>(null);
  // Window geometry in physical px, tracked from our own setPosition/setSize
  // calls (nothing else moves this window).
  const winPosRef = useRef({ x: 0, y: 0 });
  const moveWantedRef = useRef({ x: 0, y: 0 });
  const moveTaskRef = useRef<Promise<void> | null>(null);
  const winSizeRef = useRef({ w: 0, h: 0 });
  const interactiveRef = useRef<boolean | null>(null);
  const interactiveWantedRef = useRef(false);
  const interactiveTaskRef = useRef<Promise<void> | null>(null);
  const interactingRef = useRef(false);
  const shownRef = useRef(false);
  const visibilityTaskRef = useRef<Promise<void> | null>(null);
  // Cursor offset from the window's top-left (physical px) while dragging.
  const dragRef = useRef<{ offX: number; offY: number } | null>(null);
  const prevDownRef = useRef(true); // start "down" so a held click can't grab
  const lastDropRef = useRef<{ x: number; y: number; at: number } | null>(null);

  // Toggle window click-through (de-duped). interactive === !ignoreCursorEvents.
  const setInteractive = useCallback(async (interactive: boolean) => {
    interactiveWantedRef.current = interactive;
    if (interactiveTaskRef.current) return interactiveTaskRef.current;
    const task = (async () => {
      while (interactiveRef.current !== interactiveWantedRef.current) {
        const next = interactiveWantedRef.current;
        try {
          await getCurrentWindow().setIgnoreCursorEvents(!next);
          interactiveRef.current = next;
        } catch {
          return;
        }
      }
    })();
    interactiveTaskRef.current = task.finally(() => {
      interactiveTaskRef.current = null;
    });
    return interactiveTaskRef.current;
  }, []);

  // Re-evaluate after interaction ends too: disabling emits only one payload.
  // Serialize show/hide so a delayed show cannot complete after a newer hide.
  const syncVisibility = useCallback((): Promise<void> => {
    if (visibilityTaskRef.current) return visibilityTaskRef.current;
    const task = (async () => {
      for (;;) {
        const wantShown = overlayShouldShow(
          payloadRef.current,
          interactingRef.current,
        );
        if (!wantShown) {
          dragRef.current = null;
          interactingRef.current = false;
          setActive(false);
          await setInteractive(false);
        }
        if (wantShown === shownRef.current) return;
        try {
          const win = getCurrentWindow();
          if (wantShown) await win.show();
          else await win.hide();
          shownRef.current = wantShown;
        } catch {
          return; // Keep the last confirmed state; the next tick retries.
        }
      }
    })();
    visibilityTaskRef.current = task.finally(() => {
      visibilityTaskRef.current = null;
    });
    return visibilityTaskRef.current;
  }, [setInteractive]);

  const moveWindow = useCallback((x: number, y: number) => {
    moveWantedRef.current = { x: Math.round(x), y: Math.round(y) };
    if (moveTaskRef.current) return;
    const task = (async () => {
      while (
        winPosRef.current.x !== moveWantedRef.current.x ||
        winPosRef.current.y !== moveWantedRef.current.y
      ) {
        const next = moveWantedRef.current;
        try {
          await getCurrentWindow().setPosition(
            new PhysicalPosition(next.x, next.y),
          );
          winPosRef.current = next;
        } catch {
          return;
        }
      }
    })();
    moveTaskRef.current = task.finally(() => {
      moveTaskRef.current = null;
    });
  }, []);

  /** Place the window per config (custom spot or anchor preset). No-op while
   *  dragging, and right after a drop until the saved position round-trips
   *  otherwise a stale payload would snap the bar back to the old spot. */
  const applyConfiguredPosition = useCallback(() => {
    const p = payloadRef.current;
    const m = monitorRef.current;
    if (!p || !m || dragRef.current) return;
    const { w, h } = winSizeRef.current;
    if (w <= 0 || h <= 0) return;

    const drop = lastDropRef.current;
    if (drop) {
      const saved =
        p.customX !== null &&
        p.customY !== null &&
        Math.abs(m.x + p.customX - drop.x) < 2 &&
        Math.abs(m.y + p.customY - drop.y) < 2;
      if (saved) lastDropRef.current = null;
      else if (performance.now() - drop.at < DROP_GRACE_MS) return;
    }

    const next = overlayAnchor(m, { w, h }, p.position, p.customX, p.customY);
    moveWindow(next.x, next.y);
  }, [moveWindow]);

  // Mount: click-through immediately, then cache monitor geometry + where the
  // window currently sits.
  useEffect(() => {
    const win = getCurrentWindow();
    void (async () => {
      try {
        await setInteractive(false);
        const monitor = await currentMonitor();
        if (monitor && !validOverlayMonitor(payloadRef.current?.monitor)) {
          monitorRef.current = {
            x: monitor.position.x,
            y: monitor.position.y,
            w: monitor.size.width,
            h: monitor.size.height,
            scale: monitor.scaleFactor,
          };
        }
        const pos = await win.outerPosition();
        winPosRef.current = { x: pos.x, y: pos.y };
        applyConfiguredPosition();
      } catch {
        /* best-effort */
      }
    })();
  }, [applyConfiguredPosition, setInteractive]);

  const measureWindow = useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    const scale = window.devicePixelRatio || 1;
    const r = el.getBoundingClientRect();
    const w = Math.max(1, Math.ceil(r.width * scale));
    const h = Math.max(1, Math.ceil(r.height * scale));
    if (w === winSizeRef.current.w && h === winSizeRef.current.h) return;
    void getCurrentWindow()
      .setSize(new PhysicalSize(w, h))
      .then(() => {
        winSizeRef.current = { w, h };
        applyConfiguredPosition();
      })
      .catch(() => {});
  }, [applyConfiguredPosition]);

  // Keep the window content-sized, including after a display-scale change.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(measureWindow);
    ro.observe(el);
    return () => ro.disconnect();
  }, [measureWindow]);

  // The poll drives everything: hover detection, click-through toggling, and
  // the whole drag, from the global cursor + button state. Drag-end runs
  // unconditionally so a hidden bar or disabled payload can never strand the
  // window in an interactive state.
  useEffect(() => {
    let disposed = false;
    let timer = 0;

    const tick = async () => {
      if (disposed) return;
      try {
        if (
          overlayHeartbeatExpired(lastRenderRef.current, performance.now()) &&
          payloadRef.current
        ) {
          payloadRef.current = {
            ...payloadRef.current,
            enabled: false,
            forceHide: true,
          };
          await syncVisibility();
        }
        const m = monitorRef.current;
        if (shownRef.current) measureWindow();
        let over = false;

        if (
          m &&
          overlayMayInteract(payloadRef.current) &&
          (shownRef.current || dragRef.current)
        ) {
          const c = await boostCursorPos();
          if (disposed) return;
          if (!overlayMayInteract(payloadRef.current)) {
            await syncVisibility();
          } else if (dragRef.current) {
            const next = clampOverlayPosition(
              m,
              winSizeRef.current,
              c.x - dragRef.current.offX,
              c.y - dragRef.current.offY,
            );
            moveWindow(next.x, next.y);
            over = true;
            if (!c.left_down) {
              dragRef.current = null;
              lastDropRef.current = { x: next.x, y: next.y, at: performance.now() };
              void emitOverlayPosition(
                Math.round(next.x - m.x),
                Math.round(next.y - m.y),
              );
            }
          } else {
            const bar = barRef.current;
            if (bar && shownRef.current) {
              const scale = window.devicePixelRatio || 1;
              const cx = (c.x - winPosRef.current.x) / scale;
              const cy = (c.y - winPosRef.current.y) / scale;
              const r = bar.getBoundingClientRect();
              over =
                cx >= r.left - GRAB_PAD &&
                cx <= r.right + GRAB_PAD &&
                cy >= r.top - GRAB_PAD &&
                cy <= r.bottom + GRAB_PAD;
              if (over && c.left_down && !prevDownRef.current) {
                // Grab on a fresh press while over the bar.
                dragRef.current = {
                  offX: c.x - winPosRef.current.x,
                  offY: c.y - winPosRef.current.y,
                };
              }
            }
            prevDownRef.current = c.left_down;
          }
        } else {
          // Not probing, require a fresh press after re-entry so a held game
          // click can't accidentally grab the bar.
          prevDownRef.current = true;
        }

        const interacting = over || dragRef.current !== null;
        interactingRef.current = interacting;
        if (!disposed) setActive(interacting);
        await setInteractive(interacting);
        await syncVisibility();
      } catch {
        /* ignore */
      }
      if (!disposed) {
        const delay = dragRef.current
          ? DRAG_POLL_MS
          : shownRef.current
            ? IDLE_POLL_MS
            : HIDDEN_POLL_MS;
        timer = window.setTimeout(() => void tick(), delay);
      }
    };

    void tick();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      dragRef.current = null;
      void setInteractive(false);
    };
  }, [setInteractive, moveWindow, syncVisibility, measureWindow]);

  // Render snapshots from the main window. The bar stays MOUNTED regardless of
  // payload.enabled (visibility is window show/hide only), unmounting it
  // mid-interaction is what used to kill drags and strand the window.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<OverlayRenderPayload>(OVERLAY_RENDER_EVENT, async (event) => {
      if (disposed) return;
      const p = event.payload;
      lastRenderRef.current = performance.now();
      if (validOverlayMonitor(p.monitor) && !dragRef.current) {
        if (
          monitorRef.current &&
          (monitorRef.current.x !== p.monitor.x ||
            monitorRef.current.y !== p.monitor.y)
        )
          lastDropRef.current = null;
        monitorRef.current = p.monitor;
      }
      payloadRef.current = p;
      setPayload(p);
      applyConfiguredPosition();

      await syncVisibility();
    }).then((u) => {
      if (disposed) u();
      else unlisten = u;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [syncVisibility, applyConfiguredPosition]);

  // Escape: best-effort safety hatch, cancel a drag and force click-through.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      dragRef.current = null;
      interactingRef.current = false;
      setActive(false);
      void setInteractive(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setInteractive]);

  return (
    <div ref={wrapRef} style={{ display: "inline-block", padding: 8 }}>
      {payload && (
        <>
          <div
            ref={barRef}
            style={{
              cursor: dragRef.current
                ? "grabbing"
                : active
                  ? "grab"
                  : "default",
              borderRadius: 10,
              padding: 5,
              border: active
                ? "1px dashed rgba(255,255,255,0.55)"
                : "1px dashed transparent",
              background: active ? "rgba(255,255,255,0.06)" : "transparent",
              transition: "background 120ms",
            }}
          >
            <OverlayBar
              metrics={payload.metrics}
              values={payload.values}
              size={payload.size}
              color={payload.color}
              style={payload.style}
              maxWidth={
                monitorRef.current
                  ? Math.max(
                      160,
                    monitorRef.current.w / (window.devicePixelRatio || 1) - 70,
                    )
                  : undefined
              }
            />
          </div>

          {active && (
            <div className="mt-2 flex justify-center">
              <span
                className="rounded px-2 py-1 text-[10px]"
                style={{
                  background: "rgba(0,0,0,0.72)",
                  color: "rgba(255,255,255,0.85)",
                }}
              >
                Hold &amp; drag to move
              </span>
            </div>
          )}
        </>
      )}
    </div>
  );
}
