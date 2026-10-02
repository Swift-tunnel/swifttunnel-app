import { expect, it, vi } from "vitest";
import { prepareRepair } from "./repairPreflight";

it("does not proceed when disconnect rejects", async () => {
  const read = vi.fn();
  await expect(prepareRepair({ vpnDisconnect: vi.fn().mockRejectedValue(new Error("still draining")), vpnGetState: read })).rejects.toThrow("still draining");
  expect(read).not.toHaveBeenCalled();
});

it.each(["connected", "connecting", "disconnecting", "error"])("refuses a %s tunnel after a claimed disconnect", async (state) => {
  await expect(prepareRepair({ vpnDisconnect: vi.fn().mockResolvedValue(undefined), vpnGetState: vi.fn().mockResolvedValue({ state, split_tunnel_active: false }) })).rejects.toThrow("not fully disconnected");
});

it("requires a successful state read and an inactive split tunnel", async () => {
  const deps = { vpnDisconnect: vi.fn().mockResolvedValue(undefined), vpnGetState: vi.fn().mockRejectedValue(new Error("unavailable")) };
  await expect(prepareRepair(deps)).rejects.toThrow("unavailable");
  deps.vpnGetState.mockResolvedValue({ state: "disconnected", split_tunnel_active: true });
  await expect(prepareRepair(deps)).rejects.toThrow("not fully disconnected");
  deps.vpnGetState.mockResolvedValue({ state: "disconnected", split_tunnel_active: false });
  await expect(prepareRepair(deps)).resolves.toBeUndefined();
});
