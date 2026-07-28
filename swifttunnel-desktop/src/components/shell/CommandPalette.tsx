import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { useDeepLinkStore } from "../../stores/deepLinkStore";
import { searchEntries, type SearchEntry } from "../../lib/searchIndex";

export function CommandPalette() {
  const navigateTo = useDeepLinkStore((s) => s.navigateTo);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const results = useMemo(() => searchEntries(query), [query]);

  // Ctrl/Cmd+K toggles; the topbar search button dispatches the same event.
  useEffect(() => {
    const toggle = () => setOpen((o) => !o);
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        toggle();
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("toggle-command-palette", toggle);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("toggle-command-palette", toggle);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => setIndex(0), [query]);

  // Keep the active row visible while arrowing through a long result list.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(
      `[data-row="${index}"]`,
    );
    el?.scrollIntoView({ block: "nearest" });
  }, [index]);

  if (!open) return null;

  const go = (entry: SearchEntry) => {
    if (entry.event) {
      window.dispatchEvent(new Event(entry.event));
    } else {
      navigateTo({ tab: entry.tab, game: entry.game, anchor: entry.anchor });
    }
    setOpen(false);
  };

  const onInputKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = results[index];
      if (hit) go(hit);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center px-4 pt-[14vh]"
      style={{ backgroundColor: "rgba(0,0,0,0.55)" }}
      onMouseDown={() => setOpen(false)}
    >
      <div
        className="w-full max-w-[560px] overflow-hidden rounded-[14px] shadow-2xl"
        style={{
          backgroundColor: "var(--color-bg-elevated)",
          border: "1px solid var(--color-border-default)",
        }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center gap-2.5 px-4"
          style={{
            height: 52,
            borderBottom: "1px solid var(--color-border-subtle)",
          }}
        >
          <svg
            width="17"
            height="17"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--color-text-muted)"
            strokeWidth="1.9"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKey}
            placeholder="Search anything, unlock fps, overlay, no wifi, region…"
            className="flex-1 bg-transparent text-[13.5px] text-text-primary outline-none placeholder:text-text-dimmed"
          />
          <kbd
            className="rounded-[4px] px-1.5 py-0.5 font-mono text-[10px]"
            style={{
              color: "var(--color-text-dimmed)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            Esc
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[340px] overflow-y-auto py-1.5">
          {results.length === 0 ? (
            <p className="px-4 py-6 text-center text-[12px] text-text-muted">
              No matches for “{query}”.
            </p>
          ) : (
            results.map((e, i) => (
              <button
                key={e.id}
                data-row={i}
                onClick={() => go(e)}
                onMouseMove={() => setIndex(i)}
                className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors"
                style={{
                  backgroundColor:
                    i === index ? "var(--color-bg-hover)" : "transparent",
                }}
              >
                <span
                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[7px]"
                  style={{
                    backgroundColor: "var(--color-bg-base)",
                    border: "1px solid var(--color-border-subtle)",
                  }}
                >
                  <svg
                    width="15"
                    height="15"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="var(--color-text-secondary)"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d={e.icon} />
                  </svg>
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[12.5px] font-medium text-text-primary">
                    {e.label}
                  </span>
                  <span className="block truncate text-[11px] text-text-muted">
                    {e.section}
                  </span>
                </span>
                {i === index && (
                  <kbd
                    className="shrink-0 rounded-[3px] px-1 font-mono text-[9px]"
                    style={{
                      color: "var(--color-text-dimmed)",
                      border: "1px solid var(--color-border-subtle)",
                    }}
                  >
                    ↵
                  </kbd>
                )}
              </button>
            ))
          )}
        </div>

        <div
          className="flex items-center gap-1.5 px-4 py-2 text-[10.5px] text-text-dimmed"
          style={{ borderTop: "1px solid var(--color-border-subtle)" }}
        >
          <kbd
            className="rounded-[3px] px-1 font-mono"
            style={{ border: "1px solid var(--color-border-subtle)" }}
          >
            ↑↓
          </kbd>
          <span>navigate</span>
          <kbd
            className="ml-1.5 rounded-[3px] px-1 font-mono"
            style={{ border: "1px solid var(--color-border-subtle)" }}
          >
            ↵
          </kbd>
          <span>jump to setting</span>
        </div>
      </div>
    </div>
  );
}
