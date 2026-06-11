import { useEffect, useRef, useState } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import { currentMonitor, getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { OverlayBar } from "./OverlayBar";
import {
  OVERLAY_RENDER_EVENT,
  emitOverlayEditDone,
  emitOverlayPosition,
  type OverlayRenderPayload,
} from "./overlayBus";
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

export function OverlayStatsBar() {
  const [payload, setPayload] = useState<OverlayRenderPayload | null>(null);
  const [dragPos, setDragPos] = useState<{ x: number; y: number } | null>(null);
  const drag = useRef<{ mx: number; my: number; x: number; y: number } | null>(
    null,
  );

  // Click-through by default (CRITICAL: a full-screen window that isn't
  // click-through captures every click and freezes the whole desktop), then
  // cover the active monitor.
  useEffect(() => {
    const win = getCurrentWindow();
    void (async () => {
      try {
        await win.setIgnoreCursorEvents(true);
        const monitor = await currentMonitor();
        if (!monitor) return;
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

  // Escape always exits reposition mode (a safety hatch while interactive).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void emitOverlayEditDone();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const shownRef = useRef(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<OverlayRenderPayload>(OVERLAY_RENDER_EVENT, async (event) => {
      if (disposed) return;
      const p = event.payload;
      setPayload(p);
      if (!p.editing) setDragPos(null);

      const win = getCurrentWindow();
      // ALWAYS keep click-through synced to editing (idempotent). Interactive
      // only while repositioning; click-through every other time so the overlay
      // never captures game/desktop clicks. (Set before show.)
      try {
        await win.setIgnoreCursorEvents(!p.editing);
      } catch {
        /* ignore */
      }

      const wantShown = p.enabled && p.metrics.length > 0;
      if (wantShown !== shownRef.current) {
        shownRef.current = wantShown;
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
  }, []);

  // Drag handlers (window-level so the cursor can leave the bar).
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

  const editing = payload.editing;
  const posStyle: React.CSSProperties =
    dragPos !== null
      ? { position: "absolute", left: dragPos.x, top: dragPos.y }
      : payload.customX !== null && payload.customY !== null
        ? { position: "absolute", left: payload.customX, top: payload.customY }
        : anchorStyle(payload.position);

  const onBarMouseDown = (e: React.MouseEvent) => {
    if (!editing) return;
    e.preventDefault();
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    drag.current = { mx: e.clientX, my: e.clientY, x: rect.left, y: rect.top };
    setDragPos({ x: rect.left, y: rect.top });
  };

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-transparent">
      <div style={posStyle}>
        <div
          onMouseDown={onBarMouseDown}
          style={{
            cursor: editing ? "grab" : "default",
            padding: editing ? 6 : 0,
            borderRadius: 10,
            border: editing ? "1px dashed rgba(255,255,255,0.5)" : "none",
            background: editing ? "rgba(255,255,255,0.06)" : "transparent",
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

        {editing && (
          <div className="mt-2 flex items-center gap-2">
            <span
              className="rounded px-1.5 py-1 text-[10px]"
              style={{
                background: "rgba(0,0,0,0.7)",
                color: "rgba(255,255,255,0.7)",
              }}
            >
              Drag to position
            </span>
            <button
              type="button"
              onClick={() => void emitOverlayEditDone()}
              className="rounded px-2.5 py-1 text-[10.5px] font-semibold"
              style={{ background: "#f5f5f5", color: "#0a0a0a" }}
            >
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
