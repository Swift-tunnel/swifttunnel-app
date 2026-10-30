import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import type { BindingPreflightInfo } from "../../lib/types";

const { preflight } = vi.hoisted(() => ({ preflight: { current: null as BindingPreflightInfo | null } }));
vi.mock("../../stores/vpnStore", () => ({ useVpnStore: (select: (state: object) => unknown) => select({
  bindingPreflight: preflight.current, resumeConnectWithAdapter: () => {}, dismissBindingChooser: () => {},
}) }));
vi.mock("../ui/Dialog", () => ({ Dialog: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
import { BindingChooserDialog } from "./BindingChooserDialog";

it("refuses to recommend or enable a down adapter even if an older backend recommends it", () => {
  preflight.current = {
    status: "ambiguous", reason: "fixture", network_signature: "fixture", route_resolution_source: "fixture",
    route_resolution_target_ip: null, resolved_if_index: 1, recommended_guid: "down", cached_override_used: false,
    binding_stage: null, candidates: [{ guid: "down", friendly_name: "Wi-Fi Direct", description: "", if_index: 2,
      is_up: false, is_default_route: false, kind: "wifi", stage: "smart_auto", reason: "fixture", score: 1000 }],
  };
  const html = renderToStaticMarkup(<BindingChooserDialog />);
  expect(html).not.toContain("Recommended");
  expect(html).toContain('disabled=""');
  expect(html).toContain("Unavailable");
});
