export interface Language {
  /** Google `gtx` target code. */
  code: string;
  /** English name. */
  name: string;
  /** Endonym (name in its own language). */
  native: string;
  flag: string;
}

// Codes are Google-translate compatible (note the quirks: zh-CN/zh-TW, Hebrew is
// "iw", Filipino is "tl", Norwegian is "no"). English is the source, selecting
// it restores the original strings with no API calls.
export const LANGUAGES: Language[] = [
  { code: "en", name: "English", native: "English", flag: "🇬🇧" },
  { code: "ar", name: "Arabic", native: "العربية", flag: "🇸🇦" },
  { code: "vi", name: "Vietnamese", native: "Tiếng Việt", flag: "🇻🇳" },
  { code: "es", name: "Spanish", native: "Español", flag: "🇪🇸" },
  { code: "pt", name: "Portuguese", native: "Português", flag: "🇧🇷" },
  { code: "fr", name: "French", native: "Français", flag: "🇫🇷" },
  { code: "de", name: "German", native: "Deutsch", flag: "🇩🇪" },
  { code: "ru", name: "Russian", native: "Русский", flag: "🇷🇺" },
  { code: "tr", name: "Turkish", native: "Türkçe", flag: "🇹🇷" },
  { code: "it", name: "Italian", native: "Italiano", flag: "🇮🇹" },
  { code: "pl", name: "Polish", native: "Polski", flag: "🇵🇱" },
  { code: "nl", name: "Dutch", native: "Nederlands", flag: "🇳🇱" },
  { code: "id", name: "Indonesian", native: "Indonesia", flag: "🇮🇩" },
  { code: "ms", name: "Malay", native: "Melayu", flag: "🇲🇾" },
  { code: "th", name: "Thai", native: "ไทย", flag: "🇹🇭" },
  { code: "tl", name: "Filipino", native: "Filipino", flag: "🇵🇭" },
  { code: "zh-CN", name: "Chinese (Simplified)", native: "简体中文", flag: "🇨🇳" },
  { code: "zh-TW", name: "Chinese (Traditional)", native: "繁體中文", flag: "🇹🇼" },
  { code: "ja", name: "Japanese", native: "日本語", flag: "🇯🇵" },
  { code: "ko", name: "Korean", native: "한국어", flag: "🇰🇷" },
  { code: "hi", name: "Hindi", native: "हिन्दी", flag: "🇮🇳" },
  { code: "bn", name: "Bengali", native: "বাংলা", flag: "🇧🇩" },
  { code: "ur", name: "Urdu", native: "اردو", flag: "🇵🇰" },
  { code: "fa", name: "Persian", native: "فارسی", flag: "🇮🇷" },
  { code: "iw", name: "Hebrew", native: "עברית", flag: "🇮🇱" },
  { code: "uk", name: "Ukrainian", native: "Українська", flag: "🇺🇦" },
  { code: "ro", name: "Romanian", native: "Română", flag: "🇷🇴" },
  { code: "el", name: "Greek", native: "Ελληνικά", flag: "🇬🇷" },
  { code: "cs", name: "Czech", native: "Čeština", flag: "🇨🇿" },
  { code: "hu", name: "Hungarian", native: "Magyar", flag: "🇭🇺" },
  { code: "sv", name: "Swedish", native: "Svenska", flag: "🇸🇪" },
  { code: "da", name: "Danish", native: "Dansk", flag: "🇩🇰" },
  { code: "fi", name: "Finnish", native: "Suomi", flag: "🇫🇮" },
  { code: "no", name: "Norwegian", native: "Norsk", flag: "🇳🇴" },
  { code: "sk", name: "Slovak", native: "Slovenčina", flag: "🇸🇰" },
  { code: "bg", name: "Bulgarian", native: "Български", flag: "🇧🇬" },
  { code: "hr", name: "Croatian", native: "Hrvatski", flag: "🇭🇷" },
  { code: "sr", name: "Serbian", native: "Српски", flag: "🇷🇸" },
  { code: "az", name: "Azerbaijani", native: "Azərbaycan", flag: "🇦🇿" },
  { code: "kk", name: "Kazakh", native: "Қазақ", flag: "🇰🇿" },
  { code: "uz", name: "Uzbek", native: "Oʻzbek", flag: "🇺🇿" },
  { code: "ta", name: "Tamil", native: "தமிழ்", flag: "🇮🇳" },
  { code: "te", name: "Telugu", native: "తెలుగు", flag: "🇮🇳" },
  { code: "ml", name: "Malayalam", native: "മലയാളം", flag: "🇮🇳" },
  { code: "mr", name: "Marathi", native: "मराठी", flag: "🇮🇳" },
  { code: "sw", name: "Swahili", native: "Kiswahili", flag: "🇰🇪" },
  { code: "af", name: "Afrikaans", native: "Afrikaans", flag: "🇿🇦" },
];

export function languageFor(code: string): Language {
  return LANGUAGES.find((l) => l.code === code) ?? LANGUAGES[0];
}
