/**
 * A country's flag as a small round globe.
 *
 * Emoji flags do not render on Windows (they show as two letters), so flags
 * come from SVG files in src/assets/flags, named by lowercase ISO code
 * (sg.svg, in.svg, ...). A light from the top-left and a shade at the
 * bottom-right make the disc read as a sphere. A country without a file
 * shows its code on the same globe, so a missing flag never breaks a row.
 */
const FLAG_FILES = import.meta.glob<string>("../../assets/flags/*.svg", {
  eager: true,
  query: "?url",
  import: "default",
});

function flagUrl(code: string): string | undefined {
  return FLAG_FILES[`../../assets/flags/${code.toLowerCase()}.svg`];
}

export function Flag({
  code,
  size = 20,
  className,
}: {
  code: string;
  size?: number;
  className?: string;
}) {
  const url = flagUrl(code);
  return (
    <span
      aria-hidden
      className={`relative inline-flex shrink-0 overflow-hidden rounded-full ${className ?? ""}`}
      style={{
        width: size,
        height: size,
        boxShadow: "inset 0 0 0 1px rgba(255, 255, 255, 0.14)",
      }}
    >
      {url ? (
        <img src={url} alt="" draggable={false} className="h-full w-full object-cover" />
      ) : (
        <span
          className="flex h-full w-full items-center justify-center font-semibold"
          style={{
            backgroundColor: "var(--color-bg-active)",
            color: "var(--color-text-secondary)",
            fontSize: Math.max(8, Math.round(size * 0.36)),
            letterSpacing: "0.02em",
          }}
        >
          {code.toUpperCase()}
        </span>
      )}
      <span
        className="pointer-events-none absolute inset-0 rounded-full"
        style={{
          background:
            "radial-gradient(circle at 32% 26%, rgba(255,255,255,0.38), rgba(255,255,255,0) 46%), radial-gradient(circle at 74% 80%, rgba(0,0,0,0.3), rgba(0,0,0,0) 58%)",
        }}
      />
    </span>
  );
}
