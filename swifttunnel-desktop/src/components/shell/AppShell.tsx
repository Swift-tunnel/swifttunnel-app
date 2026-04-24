import { useEffect, useRef, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { Sidebar } from "./Sidebar";
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
          <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto"
            style={{
              paddingLeft: "var(--spacing-content)",
              paddingRight: "var(--spacing-content)",
              paddingTop: "var(--spacing-content)",
              paddingBottom: "var(--spacing-content)",
            }}
          >
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
            >
              {children(activeTab)}
            </motion.div>
          </div>
        </div>
      </div>
      <ToastContainer />
      <BindingChooserDialog />
    </>
  );
}
