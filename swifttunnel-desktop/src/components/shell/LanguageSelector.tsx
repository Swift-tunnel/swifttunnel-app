import { useEffect, useMemo, useRef, useState } from "react";
import { useI18nStore } from "../../stores/i18nStore";
import { LANGUAGES, languageFor } from "../../lib/languages";

function GlobeIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z" />
    </svg>
  );
}

export function LanguageSelector() {
  const lang = useI18nStore((s) => s.lang);
  const busy = useI18nStore((s) => s.busy);
  const setLang = useI18nStore((s) => s.setLang);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const active = languageFor(lang);

  // The command palette opens this menu when you search "translate"/"language".
  useEffect(() => {
    const openMenu = () => setOpen(true);
    window.addEventListener("toggle-language-menu", openMenu);
    return () => window.removeEventListener("toggle-language-menu", openMenu);
  }, []);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return LANGUAGES;
    return LANGUAGES.filter(
      (l) =>
        l.name.toLowerCase().includes(q) ||
        l.native.toLowerCase().includes(q) ||
        l.code.toLowerCase().includes(q),
    );
  }, [query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      requestAnimationFrame(() => inputRef.current?.focus());
      const onKey = (e: KeyboardEvent) => {
        if (e.key === "Escape") setOpen(false);
      };
      window.addEventListener("keydown", onKey);
      return () => window.removeEventListener("keydown", onKey);
    }
  }, [open]);

  const choose = (code: string) => {
    setOpen(false);
    void setLang(code);
  };

  return (
    <div className="relative shrink-0">
      <button
        onClick={() => setOpen((o) => !o)}
        title="Language"
        aria-label="Change language"
        className="flex h-9 w-9 items-center justify-center rounded-full transition-[background-color] duration-150 hover:bg-[color:var(--color-bg-hover)]"
        style={{ color: open ? "var(--color-text-primary)" : "var(--color-text-muted)" }}
      >
        {busy ? (
          <span
            className="h-4 w-4 animate-spin rounded-full border-2 border-transparent"
            style={{
              borderTopColor: "var(--color-accent-primary)",
              borderRightColor: "var(--color-accent-primary)",
            }}
          />
        ) : lang === "en" ? (
          <GlobeIcon />
        ) : (
          <span className="text-[16px] leading-none">{active.flag}</span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-[90]" onMouseDown={() => setOpen(false)} />
          <div
            data-no-translate
            className="absolute right-0 z-[91] mt-2 w-[248px] overflow-hidden rounded-[12px] shadow-2xl"
            style={{
              top: "100%",
              backgroundColor: "var(--color-bg-elevated)",
              border: "1px solid var(--color-border-default)",
            }}
          >
            <div
              className="flex items-center gap-2 px-3"
              style={{ height: 42, borderBottom: "1px solid var(--color-border-subtle)" }}
            >
              <svg
                width="15"
                height="15"
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
                placeholder="Search language…"
                className="flex-1 bg-transparent text-[12.5px] text-text-primary outline-none placeholder:text-text-dimmed"
              />
            </div>

            <div className="max-h-[320px] overflow-y-auto py-1">
              {results.length === 0 ? (
                <p className="px-3 py-4 text-center text-[11.5px] text-text-muted">
                  No match.
                </p>
              ) : (
                results.map((l) => {
                  const selected = l.code === lang;
                  return (
                    <button
                      key={l.code}
                      onClick={() => choose(l.code)}
                      className="flex w-full items-center gap-2.5 px-3 py-1.5 text-left transition-colors"
                      style={{
                        backgroundColor: selected
                          ? "var(--color-accent-primary-soft-12)"
                          : "transparent",
                      }}
                      onMouseEnter={(e) => {
                        if (!selected)
                          e.currentTarget.style.backgroundColor =
                            "var(--color-bg-hover)";
                      }}
                      onMouseLeave={(e) => {
                        if (!selected)
                          e.currentTarget.style.backgroundColor = "transparent";
                      }}
                    >
                      <span className="text-[15px] leading-none">{l.flag}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12.5px] font-medium text-text-primary">
                          {l.native}
                        </span>
                        <span className="block truncate text-[10.5px] text-text-muted">
                          {l.name}
                        </span>
                      </span>
                      {selected && (
                        <svg
                          width="14"
                          height="14"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="var(--color-accent-primary)"
                          strokeWidth="2.4"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <path d="M20 6 9 17l-5-5" />
                        </svg>
                      )}
                    </button>
                  );
                })
              )}
            </div>

            <div
              className="px-3 py-2 text-[9.5px] leading-tight text-text-dimmed"
              style={{ borderTop: "1px solid var(--color-border-subtle)" }}
            >
              Auto-translated. Quality varies by language.
            </div>
          </div>
        </>
      )}
    </div>
  );
}
