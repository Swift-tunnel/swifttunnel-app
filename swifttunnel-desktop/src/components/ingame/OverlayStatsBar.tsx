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

const POLL_MS = 90;
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
  const drag = useRef<{ mx: number; my: number; x: number; y: number } | null>(
    null,
  );

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

  // Cursor poll: the bar becomes grabbable (drops click-through) only while the
  // cursor is over it, then snaps back to click-through - so it never eats game
  // clicks and can't get stuck capturing input. While dragging it stays
  // interactive regardless of where the cursor roams.
  useEffect(() => {
    let disposed = false;
    let timer = 0;
    const tick = async () => {
      if (disposed) return;
      try {
        if (drag.current) {
          if (!disposed) setActive(true);
          await setInteractive(true);
        } else {
          let over = false;
          const bar = barRef.current;
          if (bar && payloadRef.current?.enabled) {
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
          }
          if (!disposed) setActive(over);
          await setInteractive(over);
        }
      } catch {
        /* ignore */
      }
      if (!disposed) timer = window.setTimeout(() => void tick(), POLL_MS);
    };
    void tick();
    return () => {
      disposed = true;
      window.clearTimeout(timer);
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
      const wantShown = p.enabled && p.metrics.length > 0;
      if (wantShown !== shownRef.current) {
        shownRef.current = wantShown;
        if (!wantShown) {
          // Hiding: abandon any drag and go click-through.
          drag.current = null;
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
      drag.current = null;
      setDragPos(null);
      setActive(false);
      void setInteractive(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setInteractive]);

  // Drag (window-level so the cursor can leave the bar).
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!drag.current) return;
      setDragPos({
        x: drag.current.x + (e.clientX - drag.current.mx),
        y: drag.current.y + (e.clientY - drag.current.my),
      });
    };
    const onUp = () => {
      if (!drag.current) return;
      drag.current = null;
      setDragPos((p) => {
        if (p) void emitOverlayPosition(Math.round(p.x), Math.round(p.y));
        return p;
      });
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  if (!payload || !payload.enabled) {
    return <div className="h-screen w-screen bg-transparent" />;
  }

  const posStyle: React.CSSProperties =
    dragPos !== null
      ? { position: "absolute", left: dragPos.x, top: dragPos.y }
      : payload.customX !== null && payload.customY !== null
        ? { position: "absolute", left: payload.customX, top: payload.customY }
        : anchorStyle(payload.position);

  const dragging = drag.current !== null;

  const onBarMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    drag.current = { mx: e.clientX, my: e.clientY, x: rect.left, y: rect.top };
    setDragPos({ x: rect.left, y: rect.top });
  };

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-transparent">
      <div style={posStyle}>
        <div
          ref={barRef}
          onMouseDown={onBarMouseDown}
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
              Drag to move · Esc to lock
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
