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
import type { OverlayPosition } from "../../lib/types";

function anchorStyle(position: OverlayPosition): React.CSSProperties {
  const parts = position.split("-");
  const v = parts[0];
  const h = parts[1] ?? "center";
  const m = 22;
  const style: React.CSSProperties = { position: "absolute" };
  if (v === "top") style.top = m;
  else if (v === "bottom") style.bottom = m;
  else style.top = "50%";
  if (h === "left") style.left = m;
  else if (h === "right") style.right = m;
  else style.left = "50%";
  style.transform = `translate(${h === "center" ? "-50%" : "0"}, ${v === "center" ? "-50%" : "0"})`;
  return style;
}

const IDLE_POLL_MS = 110;
const DRAG_POLL_MS = 24; // smooth while dragging
// Slack (px) around the bar so it's easy to land the cursor on it to grab.
const GRAB_PAD = 8;

export function OverlayStatsBar() {
  const [payload, setPayload] = useState<OverlayRenderPayload | null>(null);
  const [dragPos, setDragPos] = useState<{ x: number; y: number } | null>(null);
  const [active, setActive] = useState(false); // cursor over bar / dragging

  const payloadRef = useRef<OverlayRenderPayload | null>(null);
  const barRef = useRef<HTMLDivElement | null>(null);
  const monitorRef = useRef({ x: 0, y: 0, scale: 1 });
  const interactiveRef = useRef(false);
  // True while the user is interacting (hovering or dragging the bar). Read by
  // the render listener so a foreground blip can't hide the bar mid-interaction.
  const interactingRef = useRef(false);
  // Offset (CSS px) of the cursor from the bar's top-left while dragging; null
  // when not dragging.
  const dragRef = useRef<{ offX: number; offY: number } | null>(null);
  const prevDownRef = useRef(true); // start "down" so a held click can't grab

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

  // Mount: click-through first (a non-click-through full-screen window captures
  // every click and freezes the desktop), then cover the active monitor and
  // cache its geometry for the cursor hit-test.
  useEffect(() => {
    const win = getCurrentWindow();
    void (async () => {
      try {
        await win.setIgnoreCursorEvents(true);
        const monitor = await currentMonitor();
        if (!monitor) return;
        monitorRef.current = {
          x: monitor.position.x,
          y: monitor.position.y,
          scale: monitor.scaleFactor,
        };
        await win.setSize(
          new PhysicalSize(monitor.size.width, monitor.size.height),
        );
        await win.setPosition(
          new PhysicalPosition(monitor.position.x, monitor.position.y),
        );
      } catch {
        /* best-effort */
      }
    })();
  }, []);

  // The poll drives EVERYTHING: hover detection, click-through toggling, and the
  // whole drag - from the global cursor + left-button state read off the OS. It
  // never relies on the webview receiving mouse events (unreliable on a
  // click-through window whose interactivity flips underneath the drag).
  useEffect(() => {
    let disposed = false;
    let timer = 0;

    const tick = async () => {
      if (disposed) return;
      try {
        const bar = barRef.current;
        const enabled = payloadRef.current?.enabled ?? false;
        let over = false;

        // Only probe the cursor when the bar could be interacted with: shown
        // (Roblox focused) or already being dragged. Otherwise the bar must not
        // light up just because the cursor passes a hidden corner.
        if (bar && (enabled || dragRef.current)) {
          const r = bar.getBoundingClientRect();
          const m = monitorRef.current;
          const c = await boostCursorPos();
          const cx = (c.x - m.x) / m.scale;
          const cy = (c.y - m.y) / m.scale;
          over =
            cx >= r.left - GRAB_PAD &&
            cx <= r.right + GRAB_PAD &&
            cy >= r.top - GRAB_PAD &&
            cy <= r.bottom + GRAB_PAD;

          if (dragRef.current) {
            // Follow the cursor; drop (and save) when the button releases.
            const next = {
              x: cx - dragRef.current.offX,
              y: cy - dragRef.current.offY,
            };
            setDragPos(next);
            if (!c.left_down) {
              dragRef.current = null;
              void emitOverlayPosition(Math.round(next.x), Math.round(next.y));
            }
          } else if (over && c.left_down && !prevDownRef.current) {
            // Grab: button pressed (rising edge) while over the bar.
            dragRef.current = { offX: cx - r.left, offY: cy - r.top };
          }

          prevDownRef.current = c.left_down;
        } else {
          // Not probing — assume the button may be down so re-entry needs a
          // fresh press to grab (no accidental grab from a held game click).
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
        timer = window.setTimeout(
          () => void tick(),
          dragRef.current ? DRAG_POLL_MS : IDLE_POLL_MS,
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
  }, [setInteractive]);

  // Render snapshots from the main window.
  const shownRef = useRef(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<OverlayRenderPayload>(OVERLAY_RENDER_EVENT, async (event) => {
      if (disposed) return;
      const p = event.payload;
      payloadRef.current = p;
      setPayload(p);

      const win = getCurrentWindow();
      // Never hide while the user is hovering or dragging the bar: a momentary
      // loss of Roblox foreground (the overlay can't avoid being clicked) must
      // not yank the bar out from under the cursor and abort the reposition.
      const wantShown =
        (p.enabled && p.metrics.length > 0) || interactingRef.current;
      if (wantShown !== shownRef.current) {
        shownRef.current = wantShown;
        if (!wantShown) {
          dragRef.current = null;
          setDragPos(null);
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
  }, [setInteractive]);

  // Escape: safety hatch - cancel a drag and force click-through.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      dragRef.current = null;
      setDragPos(null);
      setActive(false);
      void setInteractive(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setInteractive]);

  if (!payload || !payload.enabled) {
    return <div className="h-screen w-screen bg-transparent" />;
  }

  const posStyle: React.CSSProperties =
    dragPos !== null
      ? { position: "absolute", left: dragPos.x, top: dragPos.y }
      : payload.customX !== null && payload.customY !== null
        ? { position: "absolute", left: payload.customX, top: payload.customY }
        : anchorStyle(payload.position);

  const dragging = dragRef.current !== null;

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-transparent">
      <div style={posStyle}>
        <div
          ref={barRef}
          style={{
            cursor: dragging ? "grabbing" : active ? "grab" : "default",
            padding: active ? 6 : 0,
            borderRadius: 10,
            border: active
              ? "1px dashed rgba(255,255,255,0.55)"
              : "1px dashed transparent",
            background: active ? "rgba(255,255,255,0.06)" : "transparent",
            transition: "background 120ms, padding 120ms",
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
              Hold &amp; drag to move · Esc to lock
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
