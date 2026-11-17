import type { IconName } from "../components/ui/Icon";
import { REPAIR_ISSUES } from "./repairCenter";
import type { RepairIssueId } from "./repairResults";
import type { TabId } from "./types";

/** Repairs that throw away something the player set up. Never part of a
 *  symptom's first action; they live under Advanced. */
export const RESET_ISSUE_IDS: readonly RepairIssueId[] = [
  "translations",
  "overlay_layout",
  "roblox_reset",
];

export interface RepairSymptom {
  id: string;
  icon: IconName;
  /** What the player is experiencing, in their words. */
  title: string;
  blurb: string;
  /** The safest first action: its button, what it does, and what it leaves alone. */
  action: string;
  effect: string;
  issues: readonly RepairIssueId[];
  /** What to try when the first action did not help. */
  steps: string[];
  tab: TabId;
  tabAction: string;
  /** Older wording players still search for. */
  search: string[];
}

export const REPAIR_SYMPTOMS: RepairSymptom[] = [
  {
    id: "internet",
    icon: "globe",
    title: "Internet stopped working",
    blurb: "Websites and games will not load after using SwiftTunnel.",
    action: "Restore internet",
    effect:
      "Disconnects the tunnel, then clears leftover network changes. Your Roblox and overlay settings are not touched.",
    issues: ["no_internet", "tunnel_cleanup", "windows_firewall", "adapter"],
    steps: [
      "If the result asks for a Windows restart, do that first, then test a website before reconnecting.",
      "Still offline with SwiftTunnel closed? Restart your router. The problem is then outside SwiftTunnel.",
      "If it only breaks after you connect, copy diagnostics and send them to support with the time it happened.",
    ],
    tab: "network",
    tabAction: "Open Diagnostics",
    search: ["No internet after SwiftTunnel"],
  },
  {
    id: "connect",
    icon: "connect",
    title: "Can't connect",
    blurb: "Connect fails, gets stuck, or drops straight away.",
    action: "Check connection",
    effect:
      "Disconnects the tunnel, then checks the driver, your network adapter and the relays, repairing what it safely can.",
    issues: ["driver", "adapter", "tunnel_cleanup", "windows_firewall", "relay"],
    steps: [
      "Try a different region in Connect. One relay can be down while the others work.",
      "Check your remaining free time in Connect. A session ends when the time runs out.",
      "If the result asks for a Windows restart, do that before trying again.",
      "Still failing? Copy diagnostics and send them to support with the region and the exact message.",
    ],
    tab: "connect",
    tabAction: "Open Connect",
    search: ["Driver not ready", "Connection failed"],
  },
  {
    id: "roblox",
    icon: "roblox",
    title: "Roblox won't open or join",
    blurb: "Play does nothing, Roblox closes, or you get error 279.",
    action: "Check Roblox setup",
    effect:
      "Disconnects the tunnel, then checks routing, the firewall and your saved Roblox tweaks. It does not reset them.",
    issues: ["route_assist", "roblox", "windows_firewall", "relay"],
    steps: [
      "Disconnect and join the same game without SwiftTunnel. Note whether that works.",
      "If it works only without the tunnel, try another region, then copy diagnostics right after a failed join.",
      "If Roblox opened but SwiftTunnel said it did not, copy diagnostics straight away so the log still has it.",
      "Last resort: Advanced, then Reset Roblox settings, undoes every SwiftTunnel change to the Roblox client.",
    ],
    tab: "connect",
    tabAction: "Open Connect",
    search: ["Connected, but Roblox cannot join (error 279 or no returning traffic)"],
  },
  {
    id: "update",
    icon: "refresh",
    title: "Update failed",
    blurb: "The update will not download, install, or finish.",
    action: "Check install",
    effect: "Disconnects the tunnel, then checks how SwiftTunnel is installed. Nothing else is changed.",
    issues: ["installer"],
    steps: [
      "Write down the exact message, and the package name if Windows asks for one. Do not delete the Windows Installer cache.",
      "Install over the top with the current official SwiftTunnel installer. Do not download single DLL files from other sites.",
      "If Windows asks for a missing package, send support the message and your installed version so they can find the matching one.",
    ],
    tab: "settings",
    tabAction: "Open version and updates",
    search: ["Windows Installer asks for an unavailable resource, or uninstall fails"],
  },
  {
    id: "lag",
    icon: "gauge",
    title: "Lag, low FPS or disconnects",
    blurb: "The game stutters, the app freezes, or you drop mid-game.",
    action: "Check for causes",
    effect: "Disconnects the tunnel, then measures the relays and reads your boost settings. Nothing else is changed.",
    issues: ["relay", "network_booster", "adapter"],
    steps: [
      "Compare the same Roblox scene with the overlay off. If the problem started after a tweak, turn that tweak off in Optimize.",
      "For disconnects, note how often they happen, the region and the exact message, and check your remaining free time in Connect.",
      "Copy diagnostics right after the next disconnect. A relay outage cannot be repaired from your PC.",
    ],
    tab: "network",
    tabAction: "Open Diagnostics",
    search: [
      "Lower FPS, a white window, or the app stops responding",
      "Disconnects at a regular interval",
    ],
  },
  {
    id: "unsure",
    icon: "repair",
    title: "Something else",
    blurb: "Not sure what is wrong, or several things at once.",
    action: "Run safe repair",
    effect:
      "Disconnects the tunnel, then runs every check and repair that keeps your settings as they are.",
    issues: REPAIR_ISSUES.map((issue) => issue.id).filter(
      (id) => !RESET_ISSUE_IDS.includes(id),
    ),
    steps: [
      "Follow any step the result lists, such as restarting Windows.",
      "Then copy diagnostics and send them to support with what you were doing and when it went wrong.",
    ],
    tab: "network",
    tabAction: "Open Diagnostics",
    search: [],
  },
];

export interface AdvancedRepair {
  id: string;
  label: string;
  /** What the player loses or has to sit through. Shown before confirming. */
  warning: string;
  action: string;
  issues: readonly RepairIssueId[];
}

/** Driver reinstall is listed beside these in the tab but runs through its own
 *  path (`runDriverReinstall`), so it is not in this list. */
export const ADVANCED_REPAIRS: AdvancedRepair[] = [
  {
    id: "overlay_layout",
    label: "Reset overlay position",
    warning: "Moves the in-game overlay back to the top left at its small size.",
    action: "Reset overlay",
    issues: ["overlay_layout"],
  },
  {
    id: "translations",
    label: "Reset translations",
    warning: "Clears the saved translations and translates the app again.",
    action: "Reset translations",
    issues: ["translations"],
  },
  {
    id: "roblox_reset",
    label: "Reset Roblox settings",
    warning:
      "Removes every SwiftTunnel change to the Roblox client: FFlags, FPS unlock, window size and graphics. You will need to set them up again.",
    action: "Reset Roblox settings",
    issues: ["roblox_reset"],
  },
  {
    id: "full",
    label: "Full repair and reset",
    warning:
      "Runs every repair and all three resets above. SwiftTunnel restarts if anything was changed.",
    action: "Run full repair",
    issues: REPAIR_ISSUES.map((issue) => issue.id),
  },
];
