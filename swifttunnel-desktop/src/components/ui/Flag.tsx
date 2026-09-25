import { Icon } from "./Icon";

/**
 * A country's flag as a small round badge.
 *
 * Emoji flags do not render on Windows (they show as two letters), so the
 * flags are our own 32x32 drawings in src/assets/flags, named by lowercase ISO
 * code (sg.svg, in.svg, ...), cropped to a circle here with a grey edge.
 * `highlight` turns the edge light, for the region in use. A country without
 * a drawing shows a plain globe.
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

const EDGE = "#5b5b64";

export function Flag({
  code,
  size = 20,
  highlight = false,
  className,
}: {
  code: string;
  size?: number;
  /** Light edge, for the region the tunnel uses or the one selected. */
  highlight?: boolean;
  className?: string;
}) {
  const url = flagUrl(code);
  return (
    <span
      aria-hidden
      className={`relative inline-flex shrink-0 overflow-hidden rounded-full ${className ?? ""}`}
      style={{ width: size, height: size }}
    >
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
          boxShadow: `inset 0 0 0 ${size >= 18 ? 1.5 : 1}px ${
            highlight ? "var(--color-text-secondary)" : EDGE
          }`,
        }}
      />
    </span>
  );
}
