import type { TabId } from "../../lib/types";
import type { IconName } from "../ui/Icon";

export interface NavItem {
  id: TabId;
  label: string;
  description: string;
  shortcut: string;
  icon: IconName;
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

const ALL_SECTIONS: NavSection[] = [
  {
    label: "Tunnel",
    items: [
      {
        id: "connect",
        label: "Connect",
        description: "Route game traffic through the fastest relay",
        shortcut: "1",
        icon: "connect",
      },
      {
        id: "network",
        label: "Diagnostics",
        description: "Stability, speed and route health",
        shortcut: "4",
        icon: "diagnostics",
      },
    ],
  },
  {
    label: "Performance",
    items: [
      {
        id: "optimization",
        label: "Optimize",
        description: "Reversible Windows tweaks for FPS and latency",
        shortcut: "2",
        icon: "optimize",
      },
      {
        id: "games",
        label: "Games",
        description: "Roblox FPS, graphics and boosts",
        shortcut: "3",
        icon: "games",
      },
      {
        id: "ingame",
        label: "In-Game",
        description: "On-screen overlay, FPS, CPU, RAM, network",
        shortcut: "7",
        icon: "ingame",
      },
    ],
  },
  {
    label: "System",
    items: [
      { id: "license", label: "License", description: "Playtime, passes and account access", shortcut: "8", icon: "shield" },
      {
        id: "repair",
        label: "Repair",
        description: "Diagnose and fix common issues",
        shortcut: "5",
        icon: "repair",
      },
      {
        id: "settings",
        label: "Settings",
        description: "Preferences, account and updates",
        shortcut: "6",
        icon: "settings",
      },
    ],
  },
];


export const NAV_SECTIONS: NavSection[] = ALL_SECTIONS;

export const NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap((s) => s.items);

export function navItemFor(tab: string): NavItem {
  return NAV_ITEMS.find((i) => i.id === tab) ?? NAV_ITEMS[0];
}
