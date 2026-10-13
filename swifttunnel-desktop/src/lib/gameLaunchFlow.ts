import type { GameLaunchPlan, RobloxGameEntry } from "./types";

export interface GameLaunchDependencies {
  connect: (region: string | null) => Promise<void>;
  launch: () => Promise<void>;
}
export async function executeGameLaunch(plan: GameLaunchPlan, dependencies: GameLaunchDependencies) {
  if (plan.preferences.use_tunnel) await dependencies.connect(plan.relay_region);
  await dependencies.launch();
}
export function defaultGamePreferences(entry: RobloxGameEntry) {
  return entry.preferences ?? { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false };
}
