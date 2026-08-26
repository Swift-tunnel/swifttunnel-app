/**
 * SwiftTunnel Lite: the same app with most of it removed.
 *
 * Lite is not a second client. It is this codebase built with a flag, so every
 * screen it keeps is the real component, with the real design system, the real
 * fonts and the real behaviour. Three earlier attempts at hand-building a
 * native window failed for the obvious reason: reimplementing a design system
 * in a drawing API gets you something that resembles the product at best, and
 * the resemblance was never good enough.
 *
 * What Lite is for: players who want the tunnel and the frame cap and nothing
 * else, on a machine where the full app's extra surface is not wanted.
 *
 * Set at build time, never at runtime, so Vite can drop the unused screens from
 * the bundle rather than shipping them behind a branch nobody takes.
 */
export const IS_LITE = import.meta.env.VITE_SWIFTTUNNEL_LITE === "1";

/**
 * The three pages Lite keeps.
 *
 * `games` is reused rather than given a new id: it already carries the Roblox
 * tuning, and inventing a `roblox` TabId would mean touching the persisted
 * settings, the command palette and the keyboard shortcuts for no gain. Lite
 * relabels it in the sidebar instead.
 */
export const LITE_TABS = ["connect", "games", "settings"] as const;

/** Where Lite opens, since Home is one of the screens it drops. */
export const LITE_DEFAULT_TAB = "connect";

/**
 * Roblox-page settings Lite does not render.
 *
 * These are the System, Network and Process Scheduling sections, which are
 * Windows tuning rather than game or tunnel settings, so Lite drops them and
 * leaves that job to the full app's Optimize page.
 *
 * They need naming separately because every one of them deep-links to
 * `tab: "games"`, which Lite *does* keep. Filtering the search index by tab
 * alone leaves them in, offering a setting that is on no page and then
 * scrolling to an anchor that is not in the document.
 *
 * Must stay in step with the `!IS_LITE` guards in `BoostTab`. If a section is
 * ever added or removed there, this list moves with it.
 */
export const LITE_HIDDEN_BOOST_ANCHORS: ReadonlySet<string> = new Set([
  // System
  "high_priority",
  "timer_resolution",
  "mmcss",
  "game_mode",
  // Network
  "disable_nagle",
  "network_throttling",
  // Process Scheduling
  "gpu_binding",
  "performance_cores",
  "unbind_cpu0",
]);
