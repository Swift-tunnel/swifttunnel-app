import type { RepairCenterDeps } from "./repairCenter";

export async function prepareRepair(deps: Pick<RepairCenterDeps, "vpnDisconnect" | "vpnGetState">): Promise<void> {
  await deps.vpnDisconnect();
  const state = await deps.vpnGetState();
  if (state.state !== "disconnected" || state.split_tunnel_active) {
    throw new Error("The tunnel has not fully disconnected. Disconnect in Connect, then retry Repair. No repair steps have started.");
  }
}
