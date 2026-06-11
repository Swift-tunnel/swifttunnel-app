import type { TabId } from "../../lib/types";

export interface NavItem {
  id: TabId;
  label: string;
  description: string;
  shortcut: string;
  icon: string;
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Tunnel",
    items: [
      {
        id: "connect",
        label: "Connect",
        description: "Route game traffic through the fastest relay",
        shortcut: "1",
        icon: "M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0 M12 20h.01",
      },
      {
        id: "network",
        label: "Diagnostics",
        description: "Stability, speed and route health",
        shortcut: "4",
        icon: "M22 12h-4l-3 9L9 3l-3 9H2",
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
        icon: "M13 2L3 14h9l-1 8 10-12h-9l1-8z",
      },
      {
        id: "games",
        label: "Games",
        description: "Per-game tuning, graphics and boosts",
        shortcut: "3",
        icon: "M6 12h4 M8 10v4 M15 13h.01 M18 11h.01 M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.544-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z",
      },
      {
        id: "ingame",
        label: "In-Game",
        description: "On-screen overlay - FPS, CPU, RAM, network",
        shortcut: "7",
        icon: "M3 5h18a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z M8 21h8 M12 17v4 M6 9h5 M6 12h3",
      },
    ],
  },
  {
    label: "System",
    items: [
      {
        id: "repair",
        label: "Repair",
        description: "Diagnose and fix common issues",
        shortcut: "5",
        icon: "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.1 6.1a2.1 2.1 0 0 1-3-3l6.1-6.1a6 6 0 0 1 7.9-7.9l-3.8 3.8z",
      },
      {
        id: "settings",
        label: "Settings",
        description: "Preferences, account and updates",
        shortcut: "6",
        icon: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
      },
    ],
  },
];

export const NAV_ITEMS: NavItem[] = NAV_SECTIONS.flatMap((s) => s.items);

export function navItemFor(tab: string): NavItem {
  return NAV_ITEMS.find((i) => i.id === tab) ?? NAV_ITEMS[0];
}
