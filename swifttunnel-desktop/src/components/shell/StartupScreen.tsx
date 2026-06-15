/**
 * Brief branded screen shown at launch while the backend runs its network
 * self-heal (clears any leftover split-tunnel state from a crash/uninstall) so
 * users land on a working connection instead of a broken one. Dismissed by
 * App.tsx once the recovery reports done (or a short cap), so it never hangs.
 */
export function StartupScreen() {
  return (
    <div className="flex h-screen w-screen select-none flex-col items-center justify-center gap-6 bg-bg-base">
      <div className="flex items-center gap-2.5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent-primary/10 ring-1 ring-accent-primary/20">
          <svg
            viewBox="0 0 24 24"
            className="h-5 w-5 text-accent-primary"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M5 12.55a11 11 0 0 1 14.08 0" />
            <path d="M1.42 9a16 16 0 0 1 21.16 0" />
            <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
            <line x1="12" y1="20" x2="12.01" y2="20" />
          </svg>
        </div>
        <span className="text-lg font-semibold tracking-tight text-text-primary">
          SwiftTunnel
        </span>
      </div>

      <div className="flex flex-col items-center gap-3">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-accent-primary border-t-transparent" />
        <p className="text-[12px] text-text-muted">Preparing your connection…</p>
      </div>
    </div>
  );
}
