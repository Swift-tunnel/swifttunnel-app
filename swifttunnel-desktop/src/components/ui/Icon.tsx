import type { CSSProperties } from "react";

/**
 * The app's icon set, in one place so every icon shares a style.
 *
 * Duotone: a solid shape at low opacity under a bold rounded outline, like
 * the filled glyphs in the ExitLag client. `active` deepens the fill, which the
 * sidebar uses to mark the current tab.
 *
 * Geometry is 24x24. `fill` is the shape tinted underneath, `stroke` is the
 * outline and details drawn on top, `dot` adds solid circles.
 */
interface IconDef {
  fill?: string;
  stroke?: string;
  dot?: [number, number, number][];
  /** Draw the fill with even-odd, for shapes with holes. */
  evenOdd?: boolean;
  /** Filled glyphs with no outline (the Roblox mark). */
  solid?: boolean;
}

const ROUNDED_SQUARE =
  "M7 3h10a4 4 0 0 1 4 4v10a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4V7a4 4 0 0 1 4-4z";
const SCREEN =
  "M4 4h16a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z";
const BOLT = "M13 2 3.5 13.5h8L10.5 22 20 10.5h-8z";
const GAMEPAD =
  "M17.32 5H6.68a4 4 0 0 0-3.978 3.59C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.544-.604-6.584-.685-7.258A4 4 0 0 0 17.32 5z";
const WRENCH =
  "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94z";
const GEAR =
  "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z";
const CIRCLE_7 = "M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14z";
const CIRCLE_9 = "M12 3a9 9 0 1 1 0 18 9 9 0 0 1 0-18z";
const TRIANGLE =
  "M10.27 4a2 2 0 0 1 3.46 0l8 14A2 2 0 0 1 20 21H4a2 2 0 0 1-1.73-3z";
const SHIELD = "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z";
const ROCKET_BODY =
  "M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z";
const LAYER_TOP = "M12 3l9 5-9 5-9-5z";
const BIN = "M5 6h14l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2z";
const PANEL =
  "M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z";
const PANEL_RAIL = "M5 4h4v16H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z";

const ICONS = {
  connect: {
    fill: "M12 10.2a8.5 8.5 0 0 1 5.9 2.4L12 20l-5.9-7.4a8.5 8.5 0 0 1 5.9-2.4z",
    stroke:
      "M5 12.55a11 11 0 0 1 14.08 0 M1.42 9a16 16 0 0 1 21.16 0 M8.53 16.11a6 6 0 0 1 6.95 0",
    dot: [[12, 19.6, 1.7]],
  },
  diagnostics: {
    fill: ROUNDED_SQUARE,
    stroke: `${ROUNDED_SQUARE} M7 12h2.2l1.8-4 3 8 1.8-4H17`,
  },
  optimize: { fill: BOLT, stroke: BOLT },
  games: {
    fill: GAMEPAD,
    stroke: `${GAMEPAD} M6 12h4 M8 10v4`,
    dot: [
      [15, 13, 1.1],
      [18, 11, 1.1],
    ],
  },
  ingame: {
    fill: SCREEN,
    stroke: `${SCREEN} M8 21h8 M12 17v4 M6 9h5 M6 12.5h3`,
  },
  repair: { fill: WRENCH, stroke: WRENCH },
  settings: {
    fill: GEAR,
    stroke: `${GEAR} M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6z`,
  },
  search: { fill: CIRCLE_7, stroke: `${CIRCLE_7} M20 20l-3.9-3.9` },
  globe: {
    fill: CIRCLE_9,
    stroke: `${CIRCLE_9} M3 12h18 M12 3a14 14 0 0 1 0 18 M12 3a14 14 0 0 0 0 18`,
  },
  user: {
    fill: "M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8z M4 21a8 8 0 0 1 16 0z",
    stroke: "M12 4a4 4 0 1 1 0 8 4 4 0 0 1 0-8z M4 21a8 8 0 0 1 16 0",
  },
  sync: {
    stroke:
      "M4 12a8 8 0 0 1 13.7-5.7L20 8.6 M20 4v4.6h-4.6 M20 12a8 8 0 0 1-13.7 5.7L4 15.4 M4 20v-4.6h4.6",
  },
  info: {
    fill: CIRCLE_9,
    stroke: `${CIRCLE_9} M12 11v5`,
    dot: [[12, 7.8, 1.15]],
  },
  alert: {
    fill: CIRCLE_9,
    stroke: `${CIRCLE_9} M12 7.5v5`,
    dot: [[12, 16.2, 1.15]],
  },
  warning: {
    fill: TRIANGLE,
    stroke: `${TRIANGLE} M12 9.5v4`,
    dot: [[12, 17, 1.15]],
  },
  ban: { fill: CIRCLE_9, stroke: `${CIRCLE_9} M5.64 5.64l12.72 12.72` },
  shield: { fill: SHIELD, stroke: `${SHIELD} M9 12l2 2 4-4` },
  rocket: {
    fill: ROCKET_BODY,
    stroke: `${ROCKET_BODY} M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0 M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5`,
  },
  layers: { fill: LAYER_TOP, stroke: `${LAYER_TOP} M3 13l9 5 9-5 M3 17.5l9 5 9-5` },
  trash: {
    fill: BIN,
    stroke:
      "M3 6h18 M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2 M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6 M10 11v6 M14 11v6",
  },
  share: {
    stroke: "M4 12v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6 M16 6l-4-4-4 4 M12 2v13",
  },
  login: {
    stroke: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4 M10 17l5-5-5-5 M15 12H3",
  },
  logout: {
    stroke: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4 M16 17l5-5-5-5 M21 12H9",
  },
  "panel-close": {
    fill: PANEL_RAIL,
    stroke: `${PANEL} M9 4v16 M16.5 9.5L14 12l2.5 2.5`,
  },
  "panel-open": {
    fill: PANEL_RAIL,
    stroke: `${PANEL} M9 4v16 M14 9.5l2.5 2.5L14 14.5`,
  },
  refresh: { stroke: "M21 12a9 9 0 1 1-2.64-6.36 M21 3v6h-6" },
  pulse: { stroke: "M3 12h4l3-9 4 18 3-9h4" },
  shuffle: { stroke: "M16 3h5v5 M4 20 21 3 M21 16v5h-5 M15 15l6 6" },
  route: {
    fill: "M3 15h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1z M17 3h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z",
    stroke:
      "M3 15h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1z M17 3h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z M5 15V9a3 3 0 0 1 3-3h8",
  },
  "chevron-right": { stroke: "m9 6 6 6-6 6" },
  "chevron-left": { stroke: "m15 6-6 6 6 6" },
  "chevron-down": { stroke: "m6 9 6 6 6-6" },
  check: { stroke: "m5 12 5 5 9-10" },
  "arrow-right": { stroke: "M5 12h14 M13 6l6 6-6 6" },
  "arrow-up": { stroke: "M12 19V5 M6 11l6-6 6 6" },
  "arrow-down": { stroke: "M12 5v14 M6 13l6 6 6-6" },
  external: { stroke: "M7 17 17 7 M8 7h9v9" },
  close: { stroke: "M6 6l12 12M18 6 6 18" },
  minus: { stroke: "M5 12h14" },
  maximize: {
    stroke: "M6.5 5h11A1.5 1.5 0 0 1 19 6.5v11a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 17.5v-11A1.5 1.5 0 0 1 6.5 5z",
  },
  roblox: {
    solid: true,
    evenOdd: true,
    // A square tilted 11 degrees with a square hole, like the Roblox mark.
    fill: "M2.62 5.67L18.33 2.62L21.38 18.33L5.67 21.38z M9.3 10.18L13.82 9.3L14.7 13.82L10.18 14.7z",
  },
} satisfies Record<string, IconDef>;

export type IconName = keyof typeof ICONS;

export function Icon({
  name,
  size = 18,
  active = false,
  strokeWidth = 1.9,
  className,
  style,
}: {
  name: IconName;
  size?: number;
  /** Fill the shape in, for the selected item in a list. */
  active?: boolean;
  strokeWidth?: number;
  className?: string;
  style?: CSSProperties;
}) {
  const def: IconDef = ICONS[name];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={style}
      aria-hidden="true"
    >
      {def.fill && (
        <path
          d={def.fill}
          fill="currentColor"
          fillRule={def.evenOdd ? "evenodd" : undefined}
          fillOpacity={def.solid ? 1 : active ? 0.4 : 0.18}
          stroke="none"
        />
      )}
      {def.stroke && <path d={def.stroke} />}
      {def.dot?.map(([cx, cy, r]) => (
        <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r={r} fill="currentColor" stroke="none" />
      ))}
    </svg>
  );
}
