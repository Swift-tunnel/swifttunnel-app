import { useState } from "react";
import { motion } from "framer-motion";
import { useAuthStore } from "../../stores/authStore";
import { Button, Spinner } from "../ui";
import swiftLogo from "../../assets/swift.png";

export function BannedScreen() {
  const email = useAuthStore((s) => s.email);
  const reason = useAuthStore((s) => s.bannedReason);
  const bannedAt = useAuthStore((s) => s.bannedAt);
  const error = useAuthStore((s) => s.error);
  const logout = useAuthStore((s) => s.logout);
  const refreshProfile = useAuthStore((s) => s.refreshProfile);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    try {
      await refreshProfile();
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div
      data-tauri-drag-region
      className="flex h-screen w-screen items-center justify-center"
      style={{ backgroundColor: "var(--color-bg-base)" }}
    >
      <div className="flex w-full max-w-[380px] flex-col gap-6 px-8">
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="flex flex-col items-center gap-3 text-center"
        >
          <img
            src={swiftLogo}
            alt="SwiftTunnel"
            width={110}
            height={110}
            style={{ objectFit: "contain", filter: "grayscale(0.35)" }}
          />
          <div
            className="flex h-11 w-11 items-center justify-center rounded-[6px]"
            style={{
              backgroundColor: "rgba(244, 63, 94, 0.10)",
              border: "1px solid rgba(244, 63, 94, 0.25)",
            }}
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="rgb(251, 113, 133)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="m4.9 4.9 14.2 14.2" />
            </svg>
          </div>
          <div>
            <p className="font-mono text-[9.5px] font-semibold uppercase tracking-[0.18em] text-status-error">
              Access blocked
            </p>
            <h1 className="mt-2 text-[22px] font-semibold text-text-primary">
              Account banned
            </h1>
            <p className="mt-2 text-[12px] leading-5 text-text-muted">
              This SwiftTunnel account cannot use the desktop app.
            </p>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.05 }}
          className="space-y-3 rounded-[var(--radius-card)] p-5"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-subtle)",
          }}
        >
          {email && (
            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] text-text-muted">Account</span>
              <span className="truncate text-right font-mono text-[11px] text-text-primary">
                {email}
              </span>
            </div>
          )}
          {reason && (
            <div className="space-y-1">
              <span className="text-[11px] text-text-muted">Reason</span>
              <p className="text-[12px] leading-5 text-text-primary">
                {reason}
              </p>
            </div>
          )}
          {bannedAt && (
            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] text-text-muted">Banned</span>
              <span className="font-mono text-[11px] text-text-primary">
                {new Date(bannedAt).toLocaleString()}
              </span>
            </div>
          )}
        </motion.div>

        {error && (
          <p className="text-center text-[11px] leading-5 text-status-error">
            {error}
          </p>
        )}

        <div className="grid grid-cols-2 gap-3">
          <Button
            variant="secondary"
            size="md"
            onClick={refresh}
            disabled={refreshing}
            leadingIcon={
              refreshing ? (
                <Spinner size={14} color="currentColor" />
              ) : (
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
                  <path d="M3 21v-5h5" />
                  <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
                  <path d="M16 8h5V3" />
                </svg>
              )
            }
          >
            Refresh
          </Button>
          <Button
            variant="secondary"
            size="md"
            onClick={logout}
            leadingIcon={
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
            }
          >
            Sign out
          </Button>
        </div>
      </div>
    </div>
  );
}
