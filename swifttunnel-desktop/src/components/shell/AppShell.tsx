import { useEffect, useLayoutEffect, useRef, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { BindingChooserDialog } from "./BindingChooserDialog";
import { CommandPalette } from "./CommandPalette";
import { ToastContainer } from "../common/Toast";
import { NAV_ITEMS } from "./nav";
import { LiteTabs } from "./LiteTabs";
import { IS_LITE } from "../../lib/lite";
import { applyCachedTranslations, initI18n } from "../../lib/i18n";

interface AppShellProps {
  children: (activeTab: string) => ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  // Every sidebar item renders a digit badge, but nothing ever listened for the
  // key, the app advertised shortcuts that did nothing. Ctrl/Cmd+<digit>
  // matches the Ctrl+K palette convention.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      const item = NAV_ITEMS.find((i) => i.shortcut === e.key);
      if (!item) return;
      e.preventDefault();
      useSettingsStore.getState().setTab(item.id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // The active tab remounts in English on every switch; re-apply the saved
  // language from cache before paint so it doesn't flash English or re-fetch.
  useLayoutEffect(() => {
    // Lite ships one language, so there is nothing to re-apply and no reason
    // to walk the document on every tab change.
    if (IS_LITE) return;
    applyCachedTranslations();
  }, [activeTab]);

  // Re-apply a saved language before the browser paints, so cached translations
  // show immediately with no English flash.
  useLayoutEffect(() => {
    if (IS_LITE) return;
    initI18n();
  }, []);

  return (
    <>
      <div
        className="flex h-screen w-screen overflow-hidden rounded-[18px]"
        style={{ backgroundColor: "var(--color-bg-sidebar)" }}
      >
        {!IS_LITE && <Sidebar />}
        <div className="flex min-w-0 flex-1 flex-col pl-px pt-px">
          <TopBar />
          {/* Three pages do not need 224px of sidebar to list them. */}
          {IS_LITE && <LiteTabs />}
          <div
            ref={scrollRef}
            className="app-atmosphere flex-1 overflow-y-auto rounded-tl-[20px] border-l border-t [scrollbar-gutter:stable_both-edges]"
            style={{
              backgroundColor: "var(--color-bg-base)",
              borderColor: "var(--color-border-subtle)",
            }}
          >
            <div className="w-full min-w-0 px-6 pb-8 pt-5">
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
      <CommandPalette />
    </>
  );
}
