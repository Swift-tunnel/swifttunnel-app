import { useEffect, useRef, useState } from "react";
import { useAuthStore } from "../../stores/authStore";

const OAUTH_TIMEOUT_MS = 120_000;

export function LoginScreen() {
  const { state, error, startOAuth, pollOAuth, cancelOAuth } = useAuthStore();
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startedAtRef = useRef<number | null>(null);
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const isAwaiting = state === "awaiting_oauth";

  useEffect(() => {
    let polling = false;

    if (isAwaiting) {
      startedAtRef.current = Date.now();
      setElapsedSecs(0);

      pollRef.current = setInterval(async () => {
        if (polling) return;
        polling = true;

        const startedAt = startedAtRef.current ?? Date.now();
        const elapsedMs = Date.now() - startedAt;
        setElapsedSecs(Math.floor(elapsedMs / 1000));

        if (elapsedMs >= OAUTH_TIMEOUT_MS) {
          if (pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
          await cancelOAuth("Login timed out. Please try again.");
          polling = false;
          return;
        }

        const done = await pollOAuth();
        if (done && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
        polling = false;
      }, 1000);
    } else {
      startedAtRef.current = null;
      setElapsedSecs(0);
    }

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [cancelOAuth, isAwaiting, pollOAuth]);

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-bg-base">
      <div className="flex w-full max-w-sm flex-col items-center gap-8 px-8">
        {/* Brand */}
        <div className="flex flex-col items-center gap-3">
          <div
            className="flex h-16 w-16 items-center justify-center rounded-2xl"
            style={{
              background:
                "linear-gradient(135deg, var(--color-accent-primary), var(--color-accent-purple))",
            }}
          >
            <svg
              width="32"
              height="32"
              viewBox="0 0 24 24"
              fill="none"
              stroke="white"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-text-primary">SwiftTunnel</h1>
          <p className="text-sm text-text-secondary text-center">
            Gaming VPN with split tunneling for low-latency gameplay
          </p>
        </div>

        {/* Login Card */}
        <div
          className="flex w-full flex-col gap-4 rounded-[var(--radius-card)] border p-6"
          style={{
            backgroundColor: "var(--color-bg-card)",
            borderColor: "var(--color-border-subtle)",
          }}
        >
          {isAwaiting ? (
            <div className="flex flex-col items-center gap-3 py-4">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent-primary border-t-transparent" />
              <p className="text-sm text-text-secondary">
                Waiting for browser login...
              </p>
              <p className="text-xs text-text-muted">
                Complete sign-in in your browser to continue
              </p>
              <p className="text-xs text-text-dimmed">
                Times out in {Math.max(0, Math.ceil((OAUTH_TIMEOUT_MS / 1000) - elapsedSecs))}s
              </p>
              <button
                onClick={() => void cancelOAuth()}
                className="rounded-[var(--radius-button)] border border-border-default px-3 py-1 text-xs text-text-secondary transition-colors hover:bg-bg-hover"
              >
                Cancel
              </button>
            </div>
          ) : (
            <>
              <button
                onClick={startOAuth}
                className="flex w-full items-center justify-center gap-2 rounded-[var(--radius-button)] px-4 py-3 text-sm font-medium text-white transition-opacity hover:opacity-90"
                style={{
                  background:
                    "linear-gradient(135deg, var(--color-accent-primary), var(--color-accent-secondary))",
                }}
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
                  <polyline points="10 17 15 12 10 7" />
                  <line x1="15" y1="12" x2="3" y2="12" />
                </svg>
                Sign in with SwiftTunnel
              </button>
            </>
          )}

          {error && (
            <p className="text-xs text-status-error text-center">{error}</p>
          )}
        </div>

        <p className="text-xs text-text-dimmed">
          v{__APP_VERSION__}
        </p>
      </div>
    </div>
  );
}

declare const __APP_VERSION__: string;
