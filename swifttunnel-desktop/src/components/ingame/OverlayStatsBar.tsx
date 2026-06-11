import { useEffect, useRef, useState } from "react";
import { PhysicalPosition, PhysicalSize } from "@tauri-apps/api/dpi";
import { currentMonitor, getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { OverlayBar } from "./OverlayBar";
import { OVERLAY_RENDER_EVENT, type OverlayRenderPayload } from "./overlayBus";
import type { OverlayPosition } from "../../lib/types";

/** Absolute CSS anchor for the bar inside the full-screen overlay window. */
function anchorStyle(position: OverlayPosition): React.CSSProperties {
  const parts = position.split("-");
  const v = parts[0]; // top | center | bottom
  const h = parts[1] ?? "center"; // left | center | right
  const m = 22;
  const style: React.CSSProperties = { position: "absolute" };
  if (v === "top") style.top = m;
  else if (v === "bottom") style.bottom = m;
  else style.top = "50%";
  if (h === "left") style.left = m;
  else if (h === "right") style.right = m;
  else style.left = "50%";
  const tx = h === "center" ? "-50%" : "0";
  const ty = v === "center" ? "-50%" : "0";
  style.transform = `translate(${tx}, ${ty})`;
  return style;
}

/**
 * Root of the "overlay-stats" window: a transparent, click-through, always-on-top
 * window sized to the active monitor. Renders the live stats bar at the
 * configured position from snapshots the main window emits. Shows itself while
 * the overlay is enabled, hides otherwise.
 */
export function OverlayStatsBar() {
  const [payload, setPayload] = useState<OverlayRenderPayload | null>(null);

  // One-time: click-through + cover the active monitor.
  useEffect(() => {
    const win = getCurrentWindow();
    void win.setIgnoreCursorEvents(true);
    void (async () => {
      try {
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

  const shownRef = useRef(false);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    void listen<OverlayRenderPayload>(OVERLAY_RENDER_EVENT, (event) => {
      if (disposed) return;
      const p = event.payload;
      setPayload(p);
      const wantShown = p.enabled && p.metrics.length > 0;
      if (wantShown !== shownRef.current) {
        shownRef.current = wantShown;
        const win = getCurrentWindow();
        if (wantShown) void win.show();
        else void win.hide();
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

  if (!payload || !payload.enabled) {
    return <div className="h-screen w-screen bg-transparent" />;
  }

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-transparent">
      <div style={anchorStyle(payload.position)}>
        <OverlayBar
          metrics={payload.metrics}
          values={payload.values}
          size={payload.size}
          color={payload.color}
          style={payload.style}
        />
      </div>
    </div>
  );
}
