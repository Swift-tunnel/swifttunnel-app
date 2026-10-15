// Bound session memory and persisted JSON using the same cache budget.
export const MAX_TRANSLATION_CACHE = 1024 * 1024;
export const MAX_TRANSLATION_SOURCE = 4096;
const MAX_ENTRIES = 4096;

export class TranslationCache {
  private entries = new Map<string, { value: string; cost: number }>();
  private cost = 2;

  has(key: string): boolean { return this.entries.has(key); }

  get(key: string): string | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, translated: string): void {
    if (key.length > MAX_TRANSLATION_SOURCE) return;
    // Keep a bad/oversized service answer from growing the cache or making
    // the same label an endlessly missing translation.
    const value = translated.length > 0 && translated.length <= 8192 ? translated : key;
    // An encoded pair conservatively covers key/value escaping and separators.
    const cost = JSON.stringify([key, value]).length;
    if (cost > MAX_TRANSLATION_CACHE - 2) return;
    const old = this.entries.get(key);
    if (old) {
      this.cost -= old.cost;
      this.entries.delete(key);
    }
    while (this.entries.size >= MAX_ENTRIES || this.cost + cost > MAX_TRANSLATION_CACHE) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.cost -= this.entries.get(oldest)!.cost;
      this.entries.delete(oldest);
    }
    this.entries.set(key, { value, cost });
    this.cost += cost;
  }

  *[Symbol.iterator](): IterableIterator<[string, string]> {
    for (const [key, { value }] of this.entries) yield [key, value];
  }
}
