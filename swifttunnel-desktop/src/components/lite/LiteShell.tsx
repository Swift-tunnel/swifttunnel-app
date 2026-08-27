import { useEffect, useRef } from "react";
import { useSettingsStore } from "../../stores/settingsStore";
import { ToastContainer } from "../common/Toast";
import { BindingChooserDialog } from "../shell/BindingChooserDialog";
import { LiteNav, LiteTitleBar } from "./LiteChrome";
import { LiteConnect } from "./LiteConnect";
import { LiteRoblox } from "./LiteRoblox";
import { LiteSettings } from "./LiteSettings";

/**
 * The whole of Lite's chrome.
 *
 * Deliberately not `AppShell`. That renders a 224px sidebar, a 52px top bar
 * with a search field and a language picker, a command palette, and a wash of
 * atmosphere layers behind the content. Importing it into Lite would keep all
 * of that in the bundle whether or not it was drawn, and would keep the layout
 * that the whole exercise was about getting away from.
 *
 * What is left: a 30px title bar, three tabs, and the page. 60px of chrome in
 * a 552px window, against 52px plus a whole sidebar in the full app.
 */
export function LiteShell() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  return (
    <>
      <div
        className="flex h-screen w-screen flex-col overflow-hidden"
        style={{ backgroundColor: "var(--color-bg-base)" }}
      >
        <LiteTitleBar />
        <LiteNav />
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto overflow-x-hidden px-2.5 pb-3 pt-2.5"
        >
          {activeTab === "games" ? (
            <LiteRoblox />
          ) : activeTab === "settings" ? (
            <LiteSettings />
          ) : (
            <LiteConnect />
          )}
        </div>
      </div>
      <ToastContainer />
      {/* Kept: this is the dialog that appears when the backend cannot work out
          which adapter to bind, and without it a connect attempt on a machine
          with two live NICs stalls with nothing on screen. */}
      <BindingChooserDialog />
    </>
  );
}
