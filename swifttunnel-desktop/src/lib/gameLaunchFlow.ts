import type { GameLaunchPlan, RobloxGameEntry } from "./types";

export interface GameLaunchDependencies {
  connect: (region: string | null) => Promise<void>;
  launch: (allowUnverified: boolean) => Promise<void>;
}
export async function executeGameLaunch(plan: GameLaunchPlan, dependencies: GameLaunchDependencies) {
  if (plan.preferences.use_tunnel && plan.datacenter
    && (!plan.relay_region || plan.relay_region !== plan.datacenter.relay_region)) {
    throw new Error("The relay doesn't match the chosen location. Try Play again.");
  }
  if (plan.preferences.use_tunnel) await dependencies.connect(plan.relay_region);
  // Unknown availability is reviewed by the caller before this flow starts.
  // An initially verified plan must not silently approve an unverified server
  // if availability changes while the tunnel is connecting.
  await dependencies.launch(!!plan.job_id && plan.availability === "unknown");
}
export function verifyGameLaunchLocation(plan: GameLaunchPlan, job: string | null, explicit: number | null, preferred: boolean) {
  const expected = explicit ?? (preferred && !job && !plan.preferences.skip_matchmaker
    ? plan.preferences.datacenter_id : null);
  if (expected !== null && plan.datacenter?.id !== expected) {
    throw new Error("Your chosen location wasn't applied. Try Play again.");
  }
}
export function defaultGamePreferences(entry: RobloxGameEntry) {
  return entry.preferences ?? { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false };
}
