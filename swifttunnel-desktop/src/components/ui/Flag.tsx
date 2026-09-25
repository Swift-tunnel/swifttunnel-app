import swiftMaskUrl from "../../assets/swift-flag-mask.png";
import swiftLinesUrl from "../../assets/swift-flag-lines.png";
import { Icon } from "./Icon";

/**
 * A country's flag, as a round badge or inside the SwiftTunnel swirl.
 *
 * Emoji flags do not render on Windows (they show as two letters), so the
 * flags are our own 32x32 drawings in src/assets/flags, named by lowercase ISO
 * code (sg.svg, in.svg, ...).
 *
 * `circle` crops the flag to a circle with a grey edge. `logo` fills the
 * swirl's white bands with the flag: swift-flag-mask.png is the swirl's
 * outline, and swift-flag-lines.png its black lines and shading, laid over
 * the flag (both cut from the full-size logo in src-tauri/resources). The
 * swirl needs about 24px to read, so small spots use the circle.
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
const SWIRL_MASK = `url("${swiftMaskUrl}")`;

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

  if (shape === "logo" && url) {
    return (
      <span
        aria-hidden
        className={`relative inline-block shrink-0 ${className ?? ""}`}
        style={{ width: size, height: size }}
      >
        <span
          className="absolute inset-0"
          style={{
            // Quoted: small flags come inlined as data URLs full of single quotes.
            backgroundImage: `url("${url}")`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            WebkitMaskImage: SWIRL_MASK,
            maskImage: SWIRL_MASK,
            WebkitMaskSize: "contain",
            maskSize: "contain",
            WebkitMaskRepeat: "no-repeat",
            maskRepeat: "no-repeat",
            WebkitMaskPosition: "center",
            maskPosition: "center",
          }}
        />
        <img
          src={swiftLinesUrl}
          alt=""
          draggable={false}
          className="absolute inset-0 h-full w-full"
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
        style={{ boxShadow: `inset 0 0 0 ${size >= 18 ? 1.5 : 1}px ${EDGE}` }}
      />
    </span>
  );
}
