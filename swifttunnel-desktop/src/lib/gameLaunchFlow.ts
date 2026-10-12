import type { GameLaunchPlan, RobloxGameEntry } from "./types";
import { formatErrorMessage } from "./errors";

export interface GameLaunchDependencies {
  connect: (region: string | null) => Promise<{ owned: boolean; token: number | null }>;
  launch: (connectionStarted: boolean) => Promise<void>;
  cleanup: (token: number | null) => Promise<void>;
}
export async function executeGameLaunch(plan: GameLaunchPlan, dependencies: GameLaunchDependencies) {
  let connection: { owned: boolean; token: number | null } = { owned: false, token: null };
  try {
    if (plan.preferences.use_tunnel) connection = await dependencies.connect(plan.relay_region);
    await dependencies.launch(connection.owned);
  } catch (error) {
    if (connection.owned) {
      try { await dependencies.cleanup(connection.token); }
      catch (cleanupError) { throw new Error(`${formatErrorMessage(error)}\n\nThe automatic connection could not be stopped: ${formatErrorMessage(cleanupError)}. Open Connect and disconnect it manually.`); }
    }
    throw error;
  }
}
export function defaultGamePreferences(entry: RobloxGameEntry) {
  return entry.preferences ?? { datacenter_id: null, fps_cap: null, graphics_quality: null, use_tunnel: false };
}
