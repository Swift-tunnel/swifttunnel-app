import { Icon } from "./Icon";

/**
 * A country's flag as a small round badge.
 *
 * Emoji flags do not render on Windows (they show as two letters), so the
 * flags are our own 32x32 drawings in src/assets/flags, named by lowercase ISO
 * code (sg.svg, in.svg, ...), drawn in greys to match the app and cropped to
 * a circle here. A dark outline sets each flag off the card behind it, and
 * `highlight` adds a light ring outside that, for the region in use. A
 * country without a drawing shows a plain globe.
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

const OUTLINE = "rgba(0, 0, 0, 0.55)";
/**
 * Below this the outline is drawn inside the flag instead, so it cannot be
 * clipped by a tight row (the sidebar's region line).
 */
const OUTER_OUTLINE_MIN_SIZE = 18;

export function Flag({
  code,
  size = 20,
  highlight = false,
  className,
}: {
  code: string;
  size?: number;
  /** Light ring, for the region the tunnel uses or the one selected. */
  highlight?: boolean;
  className?: string;
}) {
  const url = flagUrl(code);
  const outer = size >= OUTER_OUTLINE_MIN_SIZE;
  return (
    <span
      aria-hidden
      className={`relative inline-flex shrink-0 rounded-full ${className ?? ""}`}
      style={{
        width: size,
        height: size,
        boxShadow: outer
          ? highlight
            ? `0 0 0 2px ${OUTLINE}, 0 0 0 3.5px var(--color-text-muted)`
            : `0 0 0 2px ${OUTLINE}`
          : undefined,
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
          style={{
            boxShadow: outer
              ? "inset 0 0 0 1px rgba(255, 255, 255, 0.1)"
              : `inset 0 0 0 1.5px ${OUTLINE}`,
          }}
        />
      </span>
    </span>
  );
}
