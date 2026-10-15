import { expect, it } from "vitest";
import { MAX_TRANSLATION_CACHE, TranslationCache } from "./translationCache";

it("keeps escaped persisted JSON within the same limit used by the loader", () => {
  const cache = new TranslationCache();
  for (let i = 0; i < 2000; i++) cache.set(`Label ${i}`, `translated ${i}:` + "\n\t\\".repeat(1000));
  const saved = JSON.stringify(Object.fromEntries(cache));
  expect(saved.length).toBeLessThanOrEqual(MAX_TRANSLATION_CACHE);
  expect(cache.has("Label 0")).toBe(false);
  expect(cache.has("Label 1999")).toBe(true);
  expect(JSON.parse(saved)["Label 1999"]).toContain("translated 1999:");
});

it("bounds short entries too and keeps recently displayed controls", () => {
  const cache = new TranslationCache();
  for (let i = 0; i < 4096; i++) cache.set(`Label ${i}`, `Translation ${i}`);
  expect(cache.get("Label 0")).toBe("Translation 0");
  cache.set("new", "New translation");
  expect(cache.has("Label 0")).toBe(true);
  expect(cache.has("Label 1")).toBe(false);
  expect([...cache]).toHaveLength(4096);
});

it("replacing entries releases their previous cost and oversized answers keep source text", () => {
  const cache = new TranslationCache();
  for (let i = 0; i < 10000; i++) cache.set("Connected", "connected:" + "x".repeat(8190));
  expect(cache.get("Connected")).toBe("Connected");
  cache.set("Connected", "Connecté");
  expect([...cache]).toEqual([["Connected", "Connecté"]]);
  cache.set("x".repeat(4097), "too long");
  expect([...cache]).toHaveLength(1);
});
