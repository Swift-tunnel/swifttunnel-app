import type { GameLaunchPlan, RobloxGameEntry } from "./types";

export interface GameLaunchDependencies {
  connect: (region: string | null) => Promise<void>;
  launch: (allowUnverified: boolean) => Promise<void>;
}
export async function executeGameLaunch(plan: GameLaunchPlan, dependencies: GameLaunchDependencies) {
  if (plan.preferences.use_tunnel) await dependencies.connect(plan.relay_region);
  // Unknown availability is reviewed by the caller before this flow starts.
  // An initially verified plan must not silently approve an unverified server
  // if availability changes while the tunnel is connecting.
  await dependencies.launch(!!plan.job_id && plan.availability === "unknown");
}
export function defaultGamePreferences(entry: RobloxGameEntry) {
  return entry.preferences ?? { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false };
}
