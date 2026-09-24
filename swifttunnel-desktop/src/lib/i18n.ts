import { invoke } from "@tauri-apps/api/core";

// ────────────────────────────────────────────────────────────────────────────
// Runtime UI translation.
//
// Rather than refactoring every string into i18n keys, we translate the live
// DOM: collect visible text nodes, machine-translate their text via a Rust
// command (Google gtx, bypasses the webview CSP and batches), then swap the
// node values. Originals are remembered so switching back to English restores
// them, and a debounced MutationObserver re-translates anything React re-renders
// or newly mounts (tab switches). Everything is cached per language, so after
// the first pass a language switch is instant and offline.
// ────────────────────────────────────────────────────────────────────────────

const STORAGE_KEY = "st.lang";
const CACHE_PREFIX = "st.i18n.";
const BATCH_SIZE = 40;
const DEBOUNCE_MS = 300;

const SKIP_TAGS = new Set([
  "SCRIPT",
  "STYLE",
  "NOSCRIPT",
  "CODE",
  "PRE",
  "TEXTAREA",
  "INPUT",
  // An <option>'s text is a data value, not UI copy, the adapter picker lists
  // hardware names ("Intel(R) Wi-Fi 6 AX201"), which must never be translated.
  // They also re-render on every adapter poll, so translating them meant a
  // fresh pass on every tab switch that never settled.
  "SELECT",
  "OPTION",
  "KBD",
  "SVG",
]);

// Weak keys let removed tabs and replaced graph labels be collected. Remember
// our last write too, so a later React update becomes the new source text.
const originals = new WeakMap<Text, { original: string; applied: string }>();
/** per-language cache: englishCore → translatedCore. */
const memCache = new Map<string, Map<string, string>>();
/**
 * `lang\u0000string` pairs the translate call threw on this session. A thrown
 * request caches nothing, so without this a string the service always rejects
 * gets re-requested on every single pass, the UI looks like it's re-translating
 * forever and never settling. Deliberately in-memory only: a restart retries.
 */
const failedStrings = new Set<string>();

let currentLang = "en";
let observer: MutationObserver | null = null;
let debounceId: number | null = null;
let running = false;
/** Bumped on every language switch to invalidate in-flight translate passes. */
let epoch = 0;

export function getStoredLang(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) || "en";
  } catch {
    return "en";
  }
}

function langCache(lang: string): Map<string, string> {
  let m = memCache.get(lang);
  if (!m) {
    m = new Map();
    try {
      const raw = localStorage.getItem(CACHE_PREFIX + lang);
      if (raw) {
        for (const [k, v] of Object.entries(JSON.parse(raw) as Record<string, string>)) {
          m.set(k, v);
        }
      }
    } catch {
      // corrupt/unavailable cache, start empty.
    }
    memCache.set(lang, m);
  }
  return m;
}

function persistCache(lang: string) {
  const m = memCache.get(lang);
  if (!m) return;
  try {
    localStorage.setItem(CACHE_PREFIX + lang, JSON.stringify(Object.fromEntries(m)));
  } catch {
    // Over quota or unavailable, translations still work in-memory this session.
  }
}

/** Worth translating? Skip numbers, symbols, single chars, pure whitespace. */
// Identifiers that must survive translation verbatim: email addresses, the
// SwiftTunnel brand name, version tags (v2.5.22), and bare URLs/handles.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VERSION_RE = /^v?\d+(\.\d+)+$/i;
const URL_RE = /^(https?:\/\/|www\.)\S+$/i;
// Live counters are data, not sentences. Translating each new throughput,
// ping or quota value creates continuous requests and grows the persisted
// cache during a connection. Keep the units as rendered by the formatter.
const MEASUREMENT_RE = /^[<>~]?\s*(?:\d+(?:[.,]\d+)*\s*(?:[kmgt]?i?b(?:\/s)?|ms|fps|[smhd])\s*)+$/i;

function isProtectedIdentifier(t: string): boolean {
  if (EMAIL_RE.test(t)) return true;
  if (VERSION_RE.test(t)) return true;
  if (URL_RE.test(t)) return true;
  // Brand name, whether alone ("SwiftTunnel") or spaced ("Swift Tunnel").
  return /^swift\s?tunnel$/i.test(t);
}

function translatable(value: string): boolean {
  const t = value.trim();
  if (t.length < 2) return false;
  if (MEASUREMENT_RE.test(t)) return false;
  if (!(/\p{L}/u.test(t) && /[a-zA-Z]/.test(t))) return false;
  return !isProtectedIdentifier(t);
}

function splitWs(raw: string): { lead: string; core: string; trail: string } {
  const lead = raw.match(/^\s*/)?.[0] ?? "";
  const trail = raw.match(/\s*$/)?.[0] ?? "";
  const core = raw.slice(lead.length, raw.length - trail.length);
  return { lead, core, trail };
}

function collectTextNodes(): Text[] {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const text = node as Text;
      const parent = text.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (parent.closest("[data-no-translate]")) return NodeFilter.FILTER_REJECT;
      // Already-translated nodes must always be revisited, otherwise switching
      // between two non-English languages (e.g. Arabic→French) would strand
      // them, since their current text no longer looks like the source.
      if (originals.has(text)) return NodeFilter.FILTER_ACCEPT;
      return translatable(text.nodeValue ?? "")
        ? NodeFilter.FILTER_ACCEPT
        : NodeFilter.FILTER_REJECT;
    },
  });
  const out: Text[] = [];
  let n: Node | null;
  while ((n = walker.nextNode())) out.push(n as Text);
  return out;
}

async function translatePerItem(chunk: string[], lang: string, cache: Map<string, string>) {
  for (const orig of chunk) {
    if (cache.has(orig)) continue;
    try {
      const t = await invoke<string>("i18n_translate", { text: orig, targetLang: lang });
      cache.set(orig, t.trim() || orig);
    } catch {
      // Don't retry this one for the rest of the session.
      failedStrings.add(`${lang}\u0000${orig}`);
    }
  }
}

async function fetchTranslations(strings: string[], lang: string) {
  const cache = langCache(lang);
  const need = [...new Set(strings)].filter(
    (s) => s && !cache.has(s) && !failedStrings.has(`${lang}\u0000${s}`),
  );
  if (!need.length) return;

  // Multi-line strings can't be safely batched (newline is the delimiter).
  const oneLine = need.filter((s) => !s.includes("\n"));
  const multiLine = need.filter((s) => s.includes("\n"));

  for (let i = 0; i < oneLine.length; i += BATCH_SIZE) {
    const chunk = oneLine.slice(i, i + BATCH_SIZE);
    try {
      const res = await invoke<string>("i18n_translate", {
        text: chunk.join("\n"),
        targetLang: lang,
      });
      const lines = res.split("\n");
      if (lines.length === chunk.length) {
        chunk.forEach((orig, idx) => cache.set(orig, lines[idx].trim() || orig));
      } else {
        // Segment count drifted, fall back to per-item for guaranteed alignment.
        await translatePerItem(chunk, lang, cache);
      }
    } catch {
      await translatePerItem(chunk, lang, cache).catch(() => {});
    }
  }

  await translatePerItem(multiLine, lang, cache).catch(() => {});
  persistCache(lang);
}

/**
 * Apply whatever is already cached for `lang`, synchronously. Returns the
 * english cores still missing from cache so the caller can fetch them. Being
 * fully synchronous (no await) is what lets a saved language apply *before* the
 * browser paints on startup, so there's no English flash / load lag.
 */
function applyCached(lang: string): string[] {
  const cache = langCache(lang);
  const missing: string[] = [];
  for (const node of collectTextNodes()) {
    const raw = node.nodeValue ?? "";
    const known = originals.get(node);
    const source = known && raw === known.applied ? known.original : raw;
    if (known && raw !== known.applied) {
      originals.delete(node);
    }
    const { lead, core: englishCore, trail } = splitWs(source);
    if (!translatable(source)) continue;
    const translated = cache.get(englishCore);
    if (translated === undefined) {
      missing.push(englishCore);
      continue;
    }
    const desired = lead + translated + trail;
    if (raw === desired) continue;
    node.nodeValue = desired;
    if (desired === source) originals.delete(node);
    else originals.set(node, { original: source, applied: desired });
  }
  return missing;
}

async function retranslate() {
  if (currentLang === "en" || running) return;
  running = true;
  observer?.disconnect();
  const myEpoch = epoch;
  try {
    const lang = currentLang;
    const missing = applyCached(lang); // instant, cache hits paint immediately
    if (missing.length) {
      await fetchTranslations(missing, lang);
      // The user may have switched language (or back to English) while the
      // fetch was in flight, applying the stale result would overwrite the
      // newer state with the old language.
      if (epoch === myEpoch) applyCached(lang);
    }
  } finally {
    running = false;
    if (currentLang !== "en") {
      ensureObserver();
      // A language change happened mid-run; redo the pass for the new one.
      if (epoch !== myEpoch) void retranslate();
    }
  }
}

function scheduleRetranslate() {
  if (debounceId != null) return;
  debounceId = window.setTimeout(() => {
    debounceId = null;
    void retranslate();
  }, DEBOUNCE_MS);
}

function ensureObserver() {
  if (!observer) {
    observer = new MutationObserver(() => scheduleRetranslate());
  }
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });
}

function restoreEnglish() {
  observer?.disconnect();
  if (debounceId != null) {
    window.clearTimeout(debounceId);
    debounceId = null;
  }
  // Visit only live document nodes. A strong list would retain every removed
  // tab and every replaced live-graph text node for the rest of the session.
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let current: Node | null;
  while ((current = walker.nextNode())) {
    const node = current as Text;
    const known = originals.get(node);
    if (known && node.nodeValue === known.applied) node.nodeValue = known.original;
    originals.delete(node);
  }
}

/** Switch the whole UI to `lang` ("en" restores originals). */
export async function applyLanguage(lang: string): Promise<void> {
  currentLang = lang;
  epoch += 1; // invalidate any in-flight pass for the previous language
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Selection just won't persist across restarts.
  }
  if (lang === "en") {
    restoreEnglish();
    return;
  }
  await retranslate();
}

/**
 * Wipe every cached translation (all languages) and, if a non-English language
 * is active, re-translate the UI from scratch. Fixes garbled, mixed-language,
 * or stale translations left by an interrupted pass or a corrupted cache.
 * Returns how many cached language stores were removed.
 */
export async function resetTranslationCache(): Promise<number> {
  let cleared = 0;
  try {
    const stale: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(CACHE_PREFIX)) stale.push(key);
    }
    for (const key of stale) {
      localStorage.removeItem(key);
      cleared++;
    }
  } catch {
    // localStorage unavailable, the in-memory reset below still applies.
  }
  memCache.clear();
  failedStrings.clear();
  if (currentLang !== "en") {
    await applyLanguage(currentLang).catch(() => {
      // Re-translation is best-effort (e.g. offline); the cache is still clean
      // and the next language pass will fetch fresh strings.
    });
  }
  return cleared;
}

/**
 * Call once on app start (from a layout effect) to re-apply a saved language.
 * `retranslate` applies cached strings synchronously before returning, so when
 * this runs pre-paint the UI never flashes English for cached content.
 */
export function initI18n(): void {
  currentLang = getStoredLang();
  if (currentLang !== "en") void retranslate();
}

/**
 * Re-apply cached translations to the current DOM synchronously. Called after a
 * tab switch remounts content in English, because everything's already cached
 * from the first visit, this flips it to the saved language *before paint*, so
 * there's no re-fetch and no English flash on every tab change.
 */
export function applyCachedTranslations(): void {
  if (currentLang === "en") return;
  applyCached(currentLang);
}
