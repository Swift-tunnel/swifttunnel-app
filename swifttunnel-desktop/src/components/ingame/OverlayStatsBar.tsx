import { useCallback, useEffect, useRef, useState } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import { currentMonitor, getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { OverlayBar } from "./OverlayBar";
import {
  OVERLAY_RENDER_EVENT,
  emitOverlayPosition,
  type OverlayRenderPayload,
} from "./overlayBus";
import { boostCursorPos } from "../../lib/commands";

const IDLE_POLL_MS = 350;
const HIDDEN_POLL_MS = 1000;
const DRAG_POLL_MS = 16; // smooth window-follow while dragging
// Slack (CSS px) around the bar so it's easy to land the cursor on it to grab.
const GRAB_PAD = 8;
/** CSS px from the monitor edge for the 3x3 anchor presets. */
const ANCHOR_MARGIN = 22;
/** After a drop, ignore payloads still carrying the pre-save position. */
const DROP_GRACE_MS = 2500;

interface MonitorInfo {
  x: number;
  y: number;
  w: number;
  h: number;
  scale: number;
}

/**
 * The stats-overlay window root. The window is sized to the BAR itself (not
 * fullscreen) — this is load-bearing: a fullscreen window that ever becomes
 * interactive captures every click on the desktop, and one stuck flag froze
 * the user's whole PC. A bar-sized window can't do that by construction.
 *
 * Dragging moves the WINDOW, driven entirely by polling the OS cursor +
 * left-button state (`boost_cursor_pos`) — never webview mouse events, which
 * are unreliable on a click-through window whose interactivity flips mid-drag.
 */
export function OverlayStatsBar() {
  const [payload, setPayload] = useState<OverlayRenderPayload | null>(null);
  const [active, setActive] = useState(false); // hovered or dragging

  const payloadRef = useRef<OverlayRenderPayload | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const barRef = useRef<HTMLDivElement | null>(null);
  const monitorRef = useRef<MonitorInfo | null>(null);
  // Window geometry in physical px, tracked from our own setPosition/setSize
  // calls (nothing else moves this window).
  const winPosRef = useRef({ x: 0, y: 0 });
  const winSizeRef = useRef({ w: 0, h: 0 });
  const interactiveRef = useRef(false);
  const interactingRef = useRef(false);
  const shownRef = useRef(false);
  // Cursor offset from the window's top-left (physical px) while dragging.
  const dragRef = useRef<{ offX: number; offY: number } | null>(null);
  const prevDownRef = useRef(true); // start "down" so a held click can't grab
  const lastDropRef = useRef<{ x: number; y: number; at: number } | null>(null);

  // Toggle window click-through (de-duped). interactive === !ignoreCursorEvents.
  const setInteractive = useCallback(async (interactive: boolean) => {
    if (interactiveRef.current === interactive) return;
    interactiveRef.current = interactive;
    try {
      await getCurrentWindow().setIgnoreCursorEvents(!interactive);
    } catch {
      /* ignore */
    }
  }, []);

  const moveWindow = useCallback((x: number, y: number) => {
    const xi = Math.round(x);
    const yi = Math.round(y);
    if (winPosRef.current.x === xi && winPosRef.current.y === yi) return;
    winPosRef.current = { x: xi, y: yi };
    void getCurrentWindow()
      .setPosition(new PhysicalPosition(xi, yi))
      .catch(() => {});
  }, []);

  /** Place the window per config (custom spot or anchor preset). No-op while
   *  dragging, and right after a drop until the saved position round-trips —
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
      else if (Date.now() - drop.at < DROP_GRACE_MS) return;
    }

    if (p.customX !== null && p.customY !== null) {
      moveWindow(m.x + p.customX, m.y + p.customY);
      return;
    }
    const margin = Math.round(ANCHOR_MARGIN * m.scale);
    const parts = p.position.split("-");
    const v = parts[0];
    const hz = parts[1] ?? "center";
    const x =
      hz === "left"
        ? m.x + margin
        : hz === "right"
          ? m.x + m.w - w - margin
          : m.x + Math.round((m.w - w) / 2);
    const y =
      v === "top"
        ? m.y + margin
        : v === "bottom"
          ? m.y + m.h - h - margin
          : m.y + Math.round((m.h - h) / 2);
    moveWindow(x, y);
  }, [moveWindow]);

  // Mount: click-through immediately, then cache monitor geometry + where the
  // window currently sits.
  useEffect(() => {
    const win = getCurrentWindow();
    void (async () => {
      try {
        await win.setIgnoreCursorEvents(true);
        const monitor = await currentMonitor();
        if (monitor) {
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
      } catch {
        /* best-effort */
      }
    })();
  }, []);

  // Keep the window exactly the size of its content (the bar + hint).
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const scale = monitorRef.current?.scale ?? window.devicePixelRatio ?? 1;
      const r = el.getBoundingClientRect();
      const w = Math.max(1, Math.ceil(r.width * scale));
      const h = Math.max(1, Math.ceil(r.height * scale));
      if (w === winSizeRef.current.w && h === winSizeRef.current.h) return;
      winSizeRef.current = { w, h };
      void getCurrentWindow()
        .setSize(new PhysicalSize(w, h))
        .catch(() => {});
      // Size feeds the anchor math (e.g. right-anchored bars).
      applyConfiguredPosition();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [applyConfiguredPosition]);

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
        const m = monitorRef.current;
        let over = false;

        if (m && (shownRef.current || dragRef.current)) {
          const c = await boostCursorPos();
          if (dragRef.current) {
            const next = {
              x: c.x - dragRef.current.offX,
              y: c.y - dragRef.current.offY,
            };
            moveWindow(next.x, next.y);
            over = true;
            if (!c.left_down) {
              dragRef.current = null;
              lastDropRef.current = { x: next.x, y: next.y, at: Date.now() };
              void emitOverlayPosition(
                Math.round(next.x - m.x),
                Math.round(next.y - m.y),
              );
            }
          } else {
            const bar = barRef.current;
            if (bar && shownRef.current) {
              const cx = (c.x - winPosRef.current.x) / m.scale;
              const cy = (c.y - winPosRef.current.y) / m.scale;
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
          // Not probing — require a fresh press after re-entry so a held game
          // click can't accidentally grab the bar.
          prevDownRef.current = true;
        }

        const interacting = over || dragRef.current !== null;
        interactingRef.current = interacting;
        if (!disposed) setActive(interacting);
        await setInteractive(interacting);
      } catch {
        /* ignore */
      }
      if (!disposed) {
        const delay = dragRef.current
          ? DRAG_POLL_MS
          : shownRef.current
            ? IDLE_POLL_MS
            : HIDDEN_POLL_MS;
        timer = window.setTimeout(
          () => void tick(),
          delay,
        );
      }
    };

    void tick();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
      dragRef.current = null;
      void setInteractive(false);
    };
  }, [setInteractive, moveWindow]);

  // Render snapshots from the main window. The bar stays MOUNTED regardless of
  // payload.enabled (visibility is window show/hide only) — unmounting it
  // mid-interaction is what used to kill drags and strand the window.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<OverlayRenderPayload>(OVERLAY_RENDER_EVENT, async (event) => {
      if (disposed) return;
      const p = event.payload;
      payloadRef.current = p;
      setPayload(p);
      applyConfiguredPosition();

      const win = getCurrentWindow();
      // Never hide while the user is hovering or dragging the bar.
      const wantShown =
        (p.enabled && p.metrics.length > 0) || interactingRef.current;
      if (wantShown !== shownRef.current) {
        shownRef.current = wantShown;
        if (!wantShown) {
          dragRef.current = null;
          interactingRef.current = false;
          setActive(false);
          await setInteractive(false);
        }
        try {
          if (wantShown) await win.show();
          else await win.hide();
        } catch {
          /* ignore */
        }
      }
    }).then((u) => {
      if (disposed) u();
      else unlisten = u;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [setInteractive, applyConfiguredPosition]);

  // Escape: best-effort safety hatch — cancel a drag and force click-through.
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
              cursor: dragRef.current ? "grabbing" : active ? "grab" : "default",
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
