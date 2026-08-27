import { useSettingsStore } from "../../stores/settingsStore";
import { NAV_ITEMS } from "./nav";

/**
 * Lite's navigation: three tabs in a row, in place of the sidebar.
 *
 * The full app's sidebar earns its width by carrying eight pages across three
 * labelled sections. Lite has three pages, which made each section a heading
 * over a single item, and 224px of chrome to show three words. Tabs say the
 * same thing in a strip, and the window gets that width back.
 *
 * Deliberately not a scaled-down copy of the sidebar. Lite is the same product,
 * not the same layout.
 */
export function LiteTabs() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);

  return (
    <nav
      className="flex shrink-0 items-center gap-0.5"
      aria-label="Sections"
    >
      {NAV_ITEMS.map((item) => {
        const selected = item.id === activeTab;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => setTab(item.id)}
            aria-current={selected ? "page" : undefined}
            title={item.description}
            className="flex items-center gap-1.5 rounded-[6px] px-2 py-1 text-[12px] font-medium"
            style={{
              backgroundColor: selected ? "var(--color-bg-hover)" : undefined,
              color: selected
                ? "var(--color-text-primary)"
                : "var(--color-text-muted)",
            }}
          >
            {/* The sidebar's icon, at the size a strip can afford. */}
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d={item.icon} />
            </svg>
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}
