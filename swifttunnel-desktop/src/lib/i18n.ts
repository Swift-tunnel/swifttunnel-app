import { invoke } from "@tauri-apps/api/core";
import { MAX_TRANSLATION_CACHE, MAX_TRANSLATION_SOURCE, TranslationCache } from "./translationCache";

// ────────────────────────────────────────────────────────────────────────────
// Runtime UI translation.
//
// Rather than refactoring every string into i18n keys, we translate the live
// DOM: collect visible text nodes, machine-translate their text via a Rust
// command (Google gtx, bypasses the webview CSP and batches), then swap the
// node values. Originals are remembered so switching back to English restores
// them, and a debounced MutationObserver re-translates anything React re-renders
// or newly mounts (tab switches). Recent translations are cached per language
// so revisiting ordinary controls does not require another network request.
// ────────────────────────────────────────────────────────────────────────────

const STORAGE_KEY = "st.lang";
const CACHE_PREFIX = "st.i18n.";
const BATCH_SIZE = 40;
const DEBOUNCE_MS = 300;
const MAX_BATCH_BYTES = 24 * 1024;
const MAX_LANGUAGES = 8;
const MAX_FAILED_STRINGS = 2048;

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
const originals = new WeakMap<Text, { original: string; applied: string; lang: string; cacheEpoch: number }>();
/** per-language cache: englishCore → translatedCore. */
const memCache = new Map<string, TranslationCache>();
let cacheEpoch = 0;
/**
 * `lang\u0000string` pairs the translate call threw on this session. A thrown
 * request caches nothing, so without this a string the service always rejects
 * gets re-requested on every single pass, the UI looks like it's re-translating
 * forever and never settling. History is bounded and in-memory only.
 */
const failedStrings = new Set<string>();

let currentLang = "en";
let observer: MutationObserver | null = null;
let debounceId: number | null = null;
let running = false;
let rerunRequested = false;
/** Bumped on every language switch to invalidate in-flight translate passes. */
let epoch = 0;

function checkedLanguage(lang: string | null): string {
  return lang && lang.length <= 16 && /^[a-z]+(?:-[a-z]+)*$/i.test(lang) ? lang : "en";
}

export function getStoredLang(): string {
  try {
    return checkedLanguage(localStorage.getItem(STORAGE_KEY));
  } catch {
    return "en";
  }
}

function langCache(lang: string): TranslationCache {
  let m = memCache.get(lang);
  if (!m) {
    m = new TranslationCache();
    try {
      const raw = localStorage.getItem(CACHE_PREFIX + lang);
      if (raw && raw.length <= MAX_TRANSLATION_CACHE) {
        const saved: unknown = JSON.parse(raw);
        if (saved && typeof saved === "object" && !Array.isArray(saved)) {
          for (const [key, value] of Object.entries(saved)) {
            // This cache is local, but old/corrupt data is not a typed dictionary.
            // Never render an object as "[object Object]" or a numeric label.
            if (key.length <= 4096 && typeof value === "string" && value.length > 0 && value.length <= 8192) {
              m.set(key, value);
            }
          }
        }
      }
    } catch {
      // corrupt/unavailable cache, start empty.
    }
    if (memCache.size >= MAX_LANGUAGES) memCache.delete(memCache.keys().next().value!);
  }
  memCache.delete(lang);
  memCache.set(lang, m);
  return m;
}

function rememberFailure(lang: string, source: string) {
  const key = `${lang}\u0000${source}`;
  failedStrings.delete(key);
  if (failedStrings.size >= MAX_FAILED_STRINGS) failedStrings.delete(failedStrings.values().next().value!);
  failedStrings.add(key);
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
  if (value.length > MAX_TRANSLATION_SOURCE) return false;
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

async function translatePerItem(chunk: string[], lang: string, cache: TranslationCache, passEpoch: number, failed: Set<string>) {
  for (const orig of chunk) {
    if (epoch !== passEpoch) return;
    if (cache.has(orig)) continue;
    try {
      const t = await invoke<string>("i18n_translate", { text: orig, targetLang: lang });
      if (epoch !== passEpoch) return;
      cache.set(orig, t.trim() || orig);
    } catch {
      if (epoch !== passEpoch) return;
      // Don't retry this one for the rest of the session.
      rememberFailure(lang, orig);
      failed.add(orig);
    }
  }
}

async function fetchTranslations(strings: string[], lang: string) {
  const failed = new Set<string>();
  const passEpoch = epoch;
  const cache = langCache(lang);
  const need = [...new Set(strings)].filter(
    (s) => s && !cache.has(s) && !failedStrings.has(`${lang}\u0000${s}`),
  );
  if (!need.length) return failed;

  // Multi-line strings can't be safely batched (newline is the delimiter).
  const oneLine = need.filter((s) => !s.includes("\n"));
  const multiLine = need.filter((s) => s.includes("\n"));
  const encoder = new TextEncoder();

  for (let i = 0; i < oneLine.length;) {
    if (epoch !== passEpoch) return failed;
    const chunk: string[] = [];
    let bytes = 0;
    while (i < oneLine.length && chunk.length < BATCH_SIZE) {
      const next = oneLine[i];
      const size = encoder.encode(next).byteLength + (chunk.length ? 1 : 0);
      if (chunk.length && bytes + size > MAX_BATCH_BYTES) break;
      chunk.push(next);
      bytes += size;
      i++;
    }
    try {
      const res = await invoke<string>("i18n_translate", {
        text: chunk.join("\n"),
        targetLang: lang,
      });
      if (epoch !== passEpoch) return failed;
      const lines = res.split("\n");
      if (lines.length === chunk.length) {
        chunk.forEach((orig, idx) => cache.set(orig, lines[idx].trim() || orig));
      } else {
        // Segment count drifted, fall back to per-item for guaranteed alignment.
        await translatePerItem(chunk, lang, cache, passEpoch, failed);
      }
    } catch {
      if (epoch !== passEpoch) return failed;
      // An unavailable/rate-limited service cannot be fixed by retrying every
      // individual label. Keep English this session; reset/restart retries.
      need.forEach(orig => { rememberFailure(lang, orig); failed.add(orig); });
      persistCache(lang);
      return failed;
    }
  }

  await translatePerItem(multiLine, lang, cache, passEpoch, failed).catch(() => {});
  if (epoch === passEpoch) persistCache(lang);
  return failed;
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
    // Evicting a cached string must not re-request a translation already on
    // this live node. Weak keys do not retain pages after navigation.
    if (known && raw === known.applied && known.lang === lang && known.cacheEpoch === cacheEpoch) continue;
    const translated = cache.get(englishCore);
    if (translated === undefined) {
      missing.push(englishCore);
      continue;
    }
    const desired = lead + translated + trail;
    if (raw !== desired) node.nodeValue = desired;
    originals.set(node, { original: source, applied: desired, lang, cacheEpoch });
  }
  return missing;
}

async function retranslate() {
  if (currentLang === "en") return;
  if (running) { rerunRequested = true; return; }
  rerunRequested = false;
  running = true;
  observer?.disconnect();
  const myEpoch = epoch;
  try {
    const lang = currentLang;
    const missing = applyCached(lang); // instant, cache hits paint immediately
    // Observe React while the network request runs. Disconnect only around
    // our synchronous DOM writes, otherwise newly mounted pages are missed.
    ensureObserver();
    if (missing.length) {
      const failed = await fetchTranslations(missing, lang);
      // The user may have switched language (or back to English) while the
      // fetch was in flight, applying the stale result would overwrite the
      // newer state with the old language.
      if (epoch === myEpoch) {
        observer?.disconnect();
        const remaining = applyCached(lang);
        const cache = langCache(lang);
        if (remaining.some(s => !cache.has(s) && !failed.has(s) && !failedStrings.has(`${lang}\u0000${s}`))) rerunRequested = true;
      }
    }
  } finally {
    running = false;
    if (currentLang !== "en") {
      ensureObserver();
      // A language change happened mid-run; redo the pass for the new one.
      if (epoch !== myEpoch || rerunRequested) { rerunRequested = false; scheduleRetranslate(); }
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

function addedNodeNeedsTranslation(node: Node): boolean {
  if (node.nodeValue != null) return translatable(node.nodeValue);
  const element = node as Element;
  if (SKIP_TAGS.has(element.tagName) || element.closest?.("[data-no-translate]")) return false;
  // Do not flatten a whole newly mounted page into one large string. A large
  // container can contain many valid short labels even when its total text
  // is over the per-label limit. Bound the observer's inspection work too.
  const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
  for (let i = 0; i < 64; i++) {
    const text = walker.nextNode() as Text | null;
    if (!text) return false;
    if (text.parentElement && !SKIP_TAGS.has(text.parentElement.tagName)
      && !text.parentElement.closest("[data-no-translate]") && translatable(text.nodeValue ?? "")) return true;
  }
  return true;
}

function ensureObserver() {
  if (!observer) {
    observer = new MutationObserver(records => {
      // Counters change several times a second. They are data, not new UI
      // copy, so avoid rescanning the whole page after every ping/FPS update.
      const needsPass = records.some(record => record.type === "characterData"
        ? translatable(record.target.nodeValue ?? "")
        : record.type === "childList" && Array.from(record.addedNodes).some(addedNodeNeedsTranslation));
      if (needsPass) scheduleRetranslate();
    });
  }
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });
}

function restoreEnglish() {
  rerunRequested = false;
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
  lang = checkedLanguage(lang);
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
  cacheEpoch++;
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
