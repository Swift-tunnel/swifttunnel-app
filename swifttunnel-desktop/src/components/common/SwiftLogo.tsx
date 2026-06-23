import { useState } from "react";
import swiftLogoUrl from "../../assets/swift.png";

type SwiftLogoProps = {
  alt?: string;
  size: number;
  className?: string;
  muted?: boolean;
};

export function SwiftLogo({
  alt = "SwiftTunnel",
  size,
  className,
  muted = false,
}: SwiftLogoProps) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return (
      <div
        aria-label={alt}
        className={`flex shrink-0 items-center justify-center rounded-full font-semibold ${className ?? ""}`}
        style={{
          width: size,
          height: size,
          color: "var(--color-text-primary)",
          background:
            "linear-gradient(135deg, var(--color-bg-elevated), var(--color-bg-active))",
          border: "1px solid var(--color-border-default)",
          fontSize: Math.max(10, Math.round(size * 0.42)),
          filter: muted ? "grayscale(0.35)" : undefined,
        }}
        role="img"
      >
        S
      </div>
    );
  }

  return (
    <img
      src={swiftLogoUrl}
      alt={alt}
      width={size}
      height={size}
      className={`shrink-0 ${className ?? ""}`}
      style={{
        width: size,
        height: size,
        objectFit: "contain",
        filter: muted ? "grayscale(0.35)" : undefined,
      }}
      onError={() => setFailed(true)}
      draggable={false}
    />
  );
}
