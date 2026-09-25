import logoMaskUrl from "../../assets/swift-flag-mask.png";
import { Icon } from "./Icon";

/**
 * A country's flag, as a round badge or in the shape of the SwiftTunnel logo.
 *
 * Emoji flags do not render on Windows (they show as two letters), so the
 * flags are our own 32x32 drawings in src/assets/flags, named by lowercase ISO
 * code (sg.svg, in.svg, ...).
 *
 * Both shapes get the same grey edge. `circle` crops the flag to a circle;
 * `logo` fills the logo's outline (the swirl's round body with the arrow's tip
 * and tail) with the flag. swift-flag-mask.png is that outline, cut from the
 * full-size logo in src-tauri/resources. The logo shape needs about 24px to
 * read, so small spots use the circle.
 *
 * A country without a drawing shows a plain globe.
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
const LOGO_MASK = {
  WebkitMaskImage: `url("${logoMaskUrl}")`,
  maskImage: `url("${logoMaskUrl}")`,
  WebkitMaskSize: "contain",
  maskSize: "contain",
  WebkitMaskRepeat: "no-repeat",
  maskRepeat: "no-repeat",
  WebkitMaskPosition: "center",
  maskPosition: "center",
} as const;

export function Flag({
  code,
  size = 20,
  shape = "circle",
  className,
}: {
  code: string;
  size?: number;
  shape?: "circle" | "logo";
  className?: string;
}) {
  const url = flagUrl(code);
  const edge = size >= 18 ? 1.5 : 1;

  if (shape === "logo" && url) {
    return (
      <span
        aria-hidden
        className={`relative inline-block shrink-0 ${className ?? ""}`}
        style={{ width: size, height: size }}
      >
        {/* The outline in grey, with the flag laid over it a little smaller,
            leaves the grey showing as an even edge all round. */}
        <span className="absolute inset-0" style={{ ...LOGO_MASK, backgroundColor: EDGE }} />
        <span
          className="absolute"
          style={{
            ...LOGO_MASK,
            inset: edge,
            // Quoted: small flags come inlined as data URLs full of single quotes.
            backgroundImage: `url("${url}")`,
            backgroundSize: "cover",
            backgroundPosition: "center",
          }}
        />
      </span>
    );
  }

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
        style={{ boxShadow: `inset 0 0 0 ${edge}px ${EDGE}` }}
      />
    </span>
  );
}
