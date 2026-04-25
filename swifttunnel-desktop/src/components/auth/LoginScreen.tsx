import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { useAuthStore } from "../../stores/authStore";
import { Button, Spinner } from "../ui";
import swiftLogo from "../../assets/swift.png";

declare const __APP_VERSION__: string;

const OAUTH_TIMEOUT_MS = 120_000;

const FEATURES = [
  {
    icon: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
    title: "Split tunneling",
    desc: "Only game traffic routes through the relay",
  },
  {
    icon: "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
    title: "Boost suite",
    desc: "FPS unlock, RAM cleaner, gaming QoS",
  },
  {
    icon: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20",
    title: "Global relay",
    desc: "28 servers across 12 regions",
  },
];

export function LoginScreen() {
  const { state, error, startOAuth, pollOAuth, cancelOAuth } = useAuthStore();
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startedAtRef = useRef<number | null>(null);
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const isAwaiting = state === "awaiting_oauth";
  const remaining = Math.max(
    0,
    Math.ceil(OAUTH_TIMEOUT_MS / 1000 - elapsedSecs),
  );

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
    <div
      data-tauri-drag-region
      className="flex h-screen w-screen items-center justify-center"
      style={{ backgroundColor: "var(--color-bg-base)" }}
    >
      <div className="flex w-full max-w-[360px] flex-col gap-6 px-8">
        {/* Brand */}
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="flex flex-col items-center gap-3"
        >
          <img
            src={swiftLogo}
            alt="SwiftTunnel"
            width={120}
            height={120}
            style={{ objectFit: "contain" }}
          />
          <div className="text-center">
            <div className="mb-2 flex items-center justify-center gap-2">
              <span
                className="h-1 w-1 rounded-full"
                style={{ backgroundColor: "var(--color-status-connected)" }}
              />
              <span className="font-mono text-[9.5px] font-semibold uppercase tracking-[0.18em] text-text-muted">
                Gaming · Relay · 28 Servers
              </span>
            </div>
            <h1 className="text-[22px] font-semibold tracking-[-0.02em] text-text-primary">
              SwiftTunnel
            </h1>
            <p className="mt-1 text-[12px] text-text-muted">
              Sign in to deploy the tunnel
            </p>
          </div>
        </motion.div>

        {/* Login card */}
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.05 }}
          className="rounded-[var(--radius-card)] p-5"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          {isAwaiting ? (
            <div className="flex flex-col items-center gap-3 py-2">
              <Spinner size={18} color="var(--color-accent-primary)" />
              <p className="text-[13px] font-medium text-text-primary">
                Waiting for browser login
              </p>
              <p className="text-center text-[11px] text-text-muted">
                Complete sign-in in your browser to continue
              </p>
              <p className="font-mono text-[10.5px] text-text-dimmed">
                Times out in {remaining}s
              </p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => void cancelOAuth()}
              >
                Cancel
              </Button>
            </div>
          ) : (
            <Button
              variant="primary"
              size="lg"
              fullWidth
              onClick={startOAuth}
              leadingIcon={
                <svg
                  width="15"
                  height="15"
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
              }
            >
              Sign in with SwiftTunnel
            </Button>
          )}

          {error && (
            <p className="mt-3 text-center text-[11px] text-status-error">
              {error}
            </p>
          )}
        </motion.div>

        {/* Feature list */}
        <div className="flex flex-col gap-1.5">
          {FEATURES.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.15 + i * 0.06, duration: 0.3 }}
              className="flex items-center gap-3 rounded-[5px] px-3 py-2"
            >
              <div
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[5px]"
                style={{
                  backgroundColor: "var(--color-accent-primary-soft-10)",
                  border: "1px solid var(--color-border-subtle)",
                }}
              >
                <svg
                  width="13"
                  height="13"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="var(--color-accent-secondary)"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d={feature.icon} />
                </svg>
              </div>
              <div>
                <div className="text-[12px] font-medium text-text-primary">
                  {feature.title}
                </div>
                <div className="text-[10.5px] text-text-muted">
                  {feature.desc}
                </div>
              </div>
            </motion.div>
          ))}
        </div>

        <p className="text-center font-mono text-[10px] text-text-dimmed">
          v{__APP_VERSION__}
        </p>
      </div>
    </div>
  );
}
