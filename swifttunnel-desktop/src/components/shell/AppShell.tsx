import { useEffect, useRef, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { BindingChooserDialog } from "./BindingChooserDialog";
import { ToastContainer } from "../common/Toast";

interface AppShellProps {
  children: (activeTab: string) => ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  return (
    <>
      <div className="flex h-screen w-screen overflow-hidden">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <div
            ref={scrollRef}
            // scrollbar-gutter: stable both-edges reserves the scrollbar's
            // width on BOTH sides so the centered content stays centered on
            // Windows (classic 8px scrollbar) as well as macOS (overlay/0px).
            // Without it, the right-only scrollbar shifts mx-auto content left.
            className="app-atmosphere flex-1 overflow-y-auto [scrollbar-gutter:stable_both-edges]"
          >
            <div className="mx-auto w-full max-w-[840px] px-6 pb-8 pt-5">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
              >
                {children(activeTab)}
              </motion.div>
            </div>
          </div>
        </div>
      </div>
      <ToastContainer />
      <BindingChooserDialog />
    </>
  );
}
