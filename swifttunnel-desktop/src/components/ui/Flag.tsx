import { Icon } from "./Icon";

/**
 * A country's flag as a small round badge.
 *
 * Emoji flags do not render on Windows (they show as two letters), so the
 * flags are our own 32x32 drawings in src/assets/flags, named by lowercase ISO
 * code (sg.svg, in.svg, ...), cropped to a circle here. A light from the
 * top-left and a darker edge give the disc some depth, and a bright rim
 * outlines it. From 18px up a ring sits just outside the disc, green when
 * `highlight` is set, for the region in use. A country without a drawing
 * shows a plain globe.
 */
const FLAG_FILES = import.meta.glob<string>("../../assets/flags/*.svg", {
  eager: true,
  query: "?url",
  import: "default",
});

// Codes the servers API may send that differ from the file names.
const ALIASES: Record<string, string> = { uk: "gb" };

function flagUrl(code: string): string | undefined {
  const key = code.toLowerCase();
  return FLAG_FILES[`../../assets/flags/${ALIASES[key] ?? key}.svg`];
}

const SHADE =
  "radial-gradient(circle at 32% 24%, rgba(255,255,255,0.32), rgba(255,255,255,0) 48%), radial-gradient(circle at 50% 50%, rgba(0,0,0,0) 60%, rgba(0,0,0,0.26) 100%)";
const RIM =
  "inset 0 1px 0 rgba(255,255,255,0.45), inset 0 0 0 1px rgba(255,255,255,0.22)";
/** Below this the outer ring crowds the text, so small flags keep the rim only. */
const RING_MIN_SIZE = 18;

export function Flag({
  code,
  size = 20,
  highlight = false,
  className,
}: {
  code: string;
  size?: number;
  /** Green ring, for the region the tunnel uses or the one selected. */
  highlight?: boolean;
  className?: string;
}) {
  const url = flagUrl(code);
  const ring = size >= RING_MIN_SIZE;
  return (
    <span
      aria-hidden
      className={`relative inline-flex shrink-0 rounded-full ${className ?? ""}`}
      style={{
        width: size,
        height: size,
        outline: ring
          ? `1.5px solid ${highlight ? "var(--color-status-connected)" : "rgba(255, 255, 255, 0.2)"}`
          : undefined,
        outlineOffset: ring ? 1.5 : undefined,
      }}
    >
      <span className="relative flex h-full w-full overflow-hidden rounded-full">
        {url ? (
          <img src={url} alt="" draggable={false} className="h-full w-full" />
        ) : (
          <span
            className="flex h-full w-full items-center justify-center"
            style={{
              backgroundColor: "var(--color-bg-active)",
              color: "var(--color-text-muted)",
            }}
          >
            <Icon name="globe" size={Math.round(size * 0.7)} strokeWidth={1.8} />
          </span>
        )}
        <span
          className="pointer-events-none absolute inset-0 rounded-full"
          style={{ background: SHADE, boxShadow: RIM }}
        />
      </span>
    </span>
  );
}
