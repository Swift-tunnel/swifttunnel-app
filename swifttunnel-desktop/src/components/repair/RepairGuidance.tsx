import { useSettingsStore } from "../../stores/settingsStore";
import type { TabId } from "../../lib/types";
import { Button } from "../ui";

const GUIDES: { title: string; steps: string[]; tab: TabId; action: string }[] = [
  {
    title: "Connected, but Roblox cannot join (error 279 or no returning traffic)",
    steps: [
      "Leave the game, disconnect, and check whether Roblox can join without the tunnel. Note which result changes.",
      "Run Repair once. If a step fails or asks for a Windows restart, follow that result before reconnecting.",
      "If it still fails, use Diagnostics and send support the repair result, log, relay region and approximate failure time. A local repair cannot fix a relay outage.",
    ], tab: "network", action: "Open Diagnostics",
  },
  {
    title: "Lower FPS, a white window, or the app stops responding",
    steps: [
      "Compare the same Roblox scene with the app visible and minimized. Note whether only FPS changes or the connection also drops.",
      "Turn off the In-Game overlay for a comparison. If the problem began after a tweak, revert that tweak in Optimize and restart the PC if it is marked Restart PC.",
      "Capture a log after the problem. Repair resets the overlay layout, but it does not turn the overlay off or revert every Windows optimization.",
    ], tab: "ingame", action: "Open In-Game",
  },
  {
    title: "Windows Installer asks for an unavailable resource, or uninstall fails",
    steps: [
      "Record the exact message and the package name Windows asks for. Keep your existing installer and do not delete the Windows Installer cache.",
      "App Repair cannot reconstruct a missing MSI from a different version. Send the message and installed version to support so they can identify the matching package.",
      "For a missing VCRUNTIME DLL, use the current official SwiftTunnel installer. Do not download individual DLLs from download sites.",
    ], tab: "settings", action: "Open version and updates",
  },
  {
    title: "Disconnects at a regular interval",
    steps: [
      "Record the interval, relay region and exact error. Check the remaining free time in Connect.",
      "Generate diagnostics after the next failure. A regular disconnect can involve renewal, connectivity or the time allowance; reinstalling the network driver is not a universal fix.",
    ], tab: "connect", action: "Open Connect",
  },
];

export function RepairGuidance() {
  const setTab = useSettingsStore((s) => s.setTab);
  return (
    <section className="instrument px-4 py-3">
      <h3 className="text-[13px] font-semibold text-text-primary">What are you trying to fix?</h3>
      <p className="mt-1 text-[12px] text-text-muted">Start with Repair above. If the problem continues, use these checks to narrow down the cause.</p>
      <div className="mt-3 divide-y divide-[color:var(--color-border-subtle)]">
        {GUIDES.map((guide) => (
          <details key={guide.title} className="py-2 text-[12px]">
            <summary className="cursor-pointer font-medium text-text-primary">{guide.title}</summary>
            <ol className="my-3 list-decimal space-y-2 pl-5 text-text-muted">{guide.steps.map((step) => <li key={step}>{step}</li>)}</ol>
            <Button variant="secondary" size="sm" onClick={() => setTab(guide.tab)}>{guide.action}</Button>
          </details>
        ))}
      </div>
    </section>
  );
}
