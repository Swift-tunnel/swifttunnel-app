import { create } from "zustand";
import { applyLanguage, getStoredLang } from "../lib/i18n";

interface I18nState {
  lang: string;
  /** True while a translation pass is in flight (first switch to a language). */
  busy: boolean;
  setLang: (lang: string) => Promise<void>;
}

export const useI18nStore = create<I18nState>((set, get) => ({
  lang: getStoredLang(),
  busy: false,
  setLang: async (lang) => {
    if (lang === get().lang) return;
    set({ lang, busy: true });
    try {
      await applyLanguage(lang);
    } finally {
      set({ busy: false });
    }
  },
}));
