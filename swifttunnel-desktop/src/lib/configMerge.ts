import type { Config } from "./types";

/** Rebase a settings read/save without discarding edits made while it ran. */
export function mergeConfigChanges(current: Config, previous: Config, incoming: Config): Config {
  function section<T extends object>(current: T, previous: T, incoming: T): T {
    const next = { ...current };
    for (const key of Object.keys(incoming) as (keyof T)[]) {
      if (JSON.stringify(current[key]) === JSON.stringify(previous[key])) next[key] = incoming[key];
    }
    return next;
  }
  return {
    ...current,
    profile: current.profile === previous.profile ? incoming.profile : current.profile,
    roblox_settings: section(current.roblox_settings, previous.roblox_settings, incoming.roblox_settings),
    network_settings: section(current.network_settings, previous.network_settings, incoming.network_settings),
    system_optimization: section(current.system_optimization, previous.system_optimization, incoming.system_optimization),
    overlay: section(current.overlay, previous.overlay, incoming.overlay),
  };
}

