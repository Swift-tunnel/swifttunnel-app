/**
 * SwiftTunnel Lite: the same product, built small.
 *
 * Lite is not a second client and not a native rewrite. It is this codebase
 * built with a flag, sharing the stores, the Rust backend, the settings file
 * and the account. What it does not share is the interface: `LiteShell` and
 * the three screens under `components/lite` are its own, because the earlier
 * version reused the full app's pages and the result was exactly what it was:
 * a 1020px app squeezed into a small window.
 *
 * What Lite is for: players who want the tunnel and the frame cap on a machine
 * that has nothing spare for anything else. It ships no sidebar, no command
 * palette, no atmosphere layers, no live graph, no overlay, no RAM cleaner, no
 * Windows tuning and no animation.
 *
 * Set at build time, never at runtime, so Rollup can drop the full app's
 * screens from the Lite bundle rather than shipping them behind a branch
 * nobody takes.
 */
export const IS_LITE = import.meta.env.VITE_SWIFTTUNNEL_LITE === "1";

/**
 * The three pages Lite keeps.
 *
 * `games` is reused rather than given a new id: it already means "the Roblox
 * page", and inventing a `roblox` TabId would mean touching the persisted
 * settings and the tab validation for no gain. Lite relabels it in the nav.
 *
 * Read by the settings store, which has to reject a persisted tab that this
 * build cannot render (someone who last used the full app on Diagnostics then
 * opens Lite).
 */
export const LITE_TABS = ["connect", "games", "settings"] as const;

/** Where Lite opens, since Home is one of the screens it drops. */
export const LITE_DEFAULT_TAB = "connect";
