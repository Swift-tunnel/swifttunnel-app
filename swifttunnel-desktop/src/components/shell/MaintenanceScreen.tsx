import { motion } from "framer-motion";
import { Button } from "../ui";
import { SwiftLogo } from "../common/SwiftLogo";
import { systemOpenUrl } from "../../lib/commands";
import { COMMUNITY_URL } from "../../lib/maintenance";

/**
 * Tunneling maintenance / downtime view. Shown inside the Connect tab while the
 * relays are down — the rest of the app (Optimize, Games, Settings, ...) keeps
 * working. Fills the tab area and points users to the community for updates.
 */
export function MaintenanceScreen() {
  return (
    <div className="flex min-h-[78vh] w-full flex-col items-center justify-center gap-9 px-8 text-center">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex flex-col items-center gap-4"
      >
        <SwiftLogo size={140} muted />
        <div
          className="flex h-14 w-14 items-center justify-center rounded-[10px]"
          style={{
            backgroundColor: "var(--color-accent-primary-soft-8)",
            border: "1px solid var(--color-border-default)",
          }}
        >
          <svg
            width="26"
            height="26"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--color-text-primary)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
          </svg>
        </div>
        <div className="flex flex-col items-center gap-3">
          <p className="font-mono text-[13px] font-semibold uppercase tracking-[0.28em] text-text-muted">
            Under maintenance
          </p>
          <h1 className="text-[34px] font-semibold leading-tight text-text-primary">
            We&rsquo;ll be right back
          </h1>
          <p className="max-w-[460px] text-[13.5px] leading-6 text-text-muted">
            Tunneling is temporarily offline while we upgrade our servers. You
            can keep using every other feature without worry. We&rsquo;re working
            on it and will be back online soon.
          </p>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.06 }}
        className="flex w-full max-w-[340px] flex-col items-center gap-2.5"
      >
        <Button
          variant="primary"
          size="lg"
          fullWidth
          onClick={() => void systemOpenUrl(COMMUNITY_URL)}
          leadingIcon={
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M20.317 4.369a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.211.375-.444.865-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.6 12.6 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.058a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.1 13.1 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.009c.12.099.246.198.373.292a.077.077 0 0 1-.006.127 12.3 12.3 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.056c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.331c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.211 0 2.176 1.096 2.157 2.42 0 1.333-.955 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.211 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
            </svg>
          }
        >
          Join the community
        </Button>
        <p className="text-[11.5px] leading-5 text-text-muted">
          Join our Discord for live updates on when tunneling is back.
        </p>
      </motion.div>
    </div>
  );
}
