import { useState } from "react";
import { motion } from "framer-motion";
import { useAuthStore } from "../../stores/authStore";
import { Button, Spinner, Icon } from "../ui";
import { SwiftLogo } from "../common/SwiftLogo";

export function formatBannedAt(bannedAt: string | null) {
  if (!bannedAt) {
    return null;
  }

  const date = new Date(bannedAt);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toLocaleString();
}

export function BannedScreen() {
  const email = useAuthStore((s) => s.email);
  const reason = useAuthStore((s) => s.bannedReason);
  const bannedAt = useAuthStore((s) => s.bannedAt);
  const error = useAuthStore((s) => s.error);
  const logout = useAuthStore((s) => s.logout);
  const refreshProfile = useAuthStore((s) => s.refreshProfile);
  const [refreshing, setRefreshing] = useState(false);
  const formattedBannedAt = formatBannedAt(bannedAt);

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
          <SwiftLogo size={110} muted />
          <div
            className="flex h-11 w-11 items-center justify-center rounded-[6px]"
            style={{
              backgroundColor: "rgba(244, 63, 94, 0.10)",
              border: "1px solid rgba(244, 63, 94, 0.25)",
            }}
          >
            <Icon name="ban" size={20} strokeWidth={2} style={{ color: "rgb(251, 113, 133)" }} />
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
          {formattedBannedAt && (
            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] text-text-muted">Banned</span>
              <span className="font-mono text-[11px] text-text-primary">
                {formattedBannedAt}
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
                <Icon name="sync" size={14} strokeWidth={2} />
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
              <Icon name="logout" size={14} strokeWidth={2} />
            }
          >
            Sign out
          </Button>
        </div>
      </div>
    </div>
  );
}
