import { useEffect, useRef, useState } from "react";
import { SwiftLogo } from "../common/SwiftLogo";
import { startupProgress, type StartupStep } from "../../lib/startup";

/**
 * Branded loading screen shown at launch while the backend runs its network
 * self-heal and the initial auth/settings/server pre-fetch complete (see
 * App.tsx). It is the first thing the window shows; there is no separate boot
 * splash.
 *
 * The bar is real: it fills one step at a time as each piece of startup
 * actually finishes, and the line under it names the step still running, so a
 * slow step (a driver repair, say) reads as work rather than a hang. App.tsx
 * caps the wait, so it never traps the user. A rotating tip keeps it from
 * feeling dead.
 */
const TIPS: string[] = [
  "SwiftTunnel only routes your game traffic, everything else stays on your ISP at full speed.",
  "Every optimization is reversible. Turn it off and the previous Windows setting comes back.",
  "The in-game overlay shows FPS, CPU, RAM and ping. Bind it to a hotkey in the In-Game tab.",
  "Auto picks the lowest-latency relay for your Roblox server automatically.",
  "Unlock Roblox's frame cap and tune graphics from the Games tab.",
  "Press Ctrl+2 for Optimize, Ctrl+3 for Games, Ctrl+7 for the in-game overlay.",
];

const TIP_INTERVAL_MS = 4200;

export function StartupScreen({ steps }: { steps: StartupStep[] }) {
  // Start on a random tip so relaunches don't always open on the same line.
  const [index, setIndex] = useState(() =>
    Math.floor(Math.random() * TIPS.length),
  );
  const [shown, setShown] = useState(true);
  const prefersReducedMotion = useRef(false);

  useEffect(() => {
    prefersReducedMotion.current =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;

    if (prefersReducedMotion.current) return;

    // Fade the current tip out, swap it, fade the next one in.
    const cycle = window.setInterval(() => {
      setShown(false);
      window.setTimeout(() => {
        setIndex((i) => (i + 1) % TIPS.length);
        setShown(true);
      }, 260);
    }, TIP_INTERVAL_MS);

    return () => window.clearInterval(cycle);
  }, []);

  const { done: doneCount, fraction: progress, current } = startupProgress(steps);

  return (
    <div className="relative flex h-screen w-screen select-none flex-col items-center justify-center overflow-hidden bg-bg-base">
      {/* Brand dot field + radial wash behind the mark so it reads as the focal
          point (matches the in-app cards). */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "radial-gradient(rgba(255,255,255,0.05) 1px, transparent 1px)",
          backgroundSize: "18px 18px",
          WebkitMaskImage:
            "radial-gradient(ellipse 60% 55% at 50% 42%, #000, transparent 78%)",
          maskImage:
            "radial-gradient(ellipse 60% 55% at 50% 42%, #000, transparent 78%)",
        }}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 42% 34% at 50% 42%, var(--color-accent-primary-soft-12, rgba(255,255,255,0.05)), transparent 70%)",
        }}
      />

      <div className="relative flex flex-col items-center">
        {/* Breathing logo mark */}
        <div className="startup-breathe">
          <SwiftLogo size={72} />
        </div>

        <span className="mt-5 text-[15px] font-semibold tracking-tight text-text-primary">
          SwiftTunnel
        </span>

        {/* Real progress, one step per piece of startup that has finished.
            It only moves when a step completes, so it costs nothing between. */}
        <div
          className="mt-6 h-[3px] w-48 overflow-hidden rounded-full bg-bg-elevated"
          role="progressbar"
          aria-label="Starting SwiftTunnel"
          aria-valuemin={0}
          aria-valuemax={steps.length}
          aria-valuenow={doneCount}
        >
          <div
            className="h-full rounded-full bg-accent-primary transition-[width] duration-500 ease-out"
            style={{ width: `${progress * 100}%` }}
          />
        </div>
        <p className="mt-2.5 h-4 text-[11.5px] text-text-muted">
          {current ?? "Ready"}
        </p>

        {/* Did-you-know rotator */}
        <div className="mt-8 flex h-16 max-w-[380px] flex-col items-center px-6 text-center">
          <span className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-accent-primary">
            Did you know?
          </span>
          <p
            className="text-[12.5px] leading-relaxed text-text-muted transition-opacity duration-300"
            style={{ opacity: shown ? 1 : 0 }}
          >
            {TIPS[index]}
          </p>
        </div>
      </div>

      <style>{`
        @keyframes startup-breathe {
          0%, 100% { transform: scale(1); opacity: 0.92; }
          50% { transform: scale(1.04); opacity: 1; }
        }
        .startup-breathe { animation: startup-breathe 3.2s ease-in-out infinite; }
        @media (prefers-reduced-motion: reduce) {
          .startup-breathe { animation: none; }
        }
      `}</style>
    </div>
  );
}
