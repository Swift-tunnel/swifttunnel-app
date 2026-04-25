# SwiftTunnel B&W Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebrand the SwiftTunnel desktop client to a strict black-and-white visual language inspired by the new `swift.png` logo, with redesigned Connect/Boost/Diagnostics/Settings/Login screens.

**Architecture:** Frontend-only redesign of the Tauri v2 + React app under `swifttunnel-desktop/`. Tokens in `globals.css` drive all surface/text/border/emphasis colors; status colors and latency ramp are preserved. The shell becomes a collapsible 48→200px icon rail with the `swift.png` logo as brand mark; the persistent `ConnectBar` is removed and Connect/Disconnect moves into the Connect screen hero.

**Tech Stack:** React 18, Tailwind v4 (`@theme` tokens in CSS), framer-motion, Lucide icons, Vitest, Tauri v2. Dev server runs on `http://localhost:1420`.

**Reference spec:** `docs/superpowers/specs/2026-04-25-bw-rebrand-design.md` — read it first. Sections referenced by task number below.

**Working directory for all commands:** `swifttunnel-app/swifttunnel-desktop/` unless stated otherwise.

**General rules:**
- Run tests after every task: `bun test` (or `npm test`). All must pass before committing.
- Verify visually in the running preview (`localhost:1420`) between tasks. Use `preview_*` tools — never ask the user to check.
- Commit after each task with the message shown. Do **not** batch commits across tasks.
- Do **not** introduce new dependencies or restructure store/logic code — this is a visual rebrand.

---

### Task 1: Overhaul design tokens in globals.css

**Files:**
- Modify: `swifttunnel-desktop/src/styles/globals.css` (full rewrite of `@theme` block)

Implements spec §Palette and §Typography.

- [ ] **Step 1: Replace the `@theme` block**

Open `src/styles/globals.css`. Replace the entire `@theme { ... }` block (lines ~5–70) with the tokens below. Leave everything outside the block alone for now (the slider `.ui-slider`/`.boost-slider` rules get restyled in Task 4).

```css
@theme {
  /* Surfaces */
  --color-bg-base: #000000;
  --color-bg-sidebar: #050505;
  --color-bg-card: #0a0a0a;
  --color-bg-elevated: #141414;
  --color-bg-hover: #1a1a1a;
  --color-bg-active: #242424;
  --color-bg-input: #0a0a0a;
  --color-bg-glass: #0e0e0e;

  /* Emphasis (replaces blue accent) */
  --color-accent-primary: #ffffff;
  --color-accent-secondary: #ffffff;
  --color-accent-primary-glow: #ffffff;
  --color-accent-primary-soft-8: rgba(255, 255, 255, 0.08);
  --color-accent-primary-soft-10: rgba(255, 255, 255, 0.1);
  --color-accent-primary-soft-12: rgba(255, 255, 255, 0.12);
  --color-accent-primary-soft-15: rgba(255, 255, 255, 0.15);
  --color-accent-primary-soft-20: rgba(255, 255, 255, 0.2);

  /* Status (preserved, one notch less saturated) */
  --color-status-connected: #22c55e;
  --color-status-connected-glow: #4ade80;
  --color-status-warning: #eab308;
  --color-status-error: #ef4444;
  --color-status-inactive: #525252;
  --color-status-warning-soft-10: rgba(234, 179, 8, 0.1);
  --color-status-error-soft-10: rgba(239, 68, 68, 0.1);
  --color-status-error-soft-20: rgba(239, 68, 68, 0.2);

  /* Text */
  --color-text-primary: #fafafa;
  --color-text-secondary: #a1a1a1;
  --color-text-muted: #6a6a6a;
  --color-text-dimmed: #3f3f3f;

  /* Borders */
  --color-border-default: #1f1f1f;
  --color-border-subtle: #141414;
  --color-border-focus: #ffffff;
  --color-border-hover: #2a2a2a;

  /* Latency (preserved, one notch less saturated) */
  --color-latency-excellent: #22c55e;
  --color-latency-good: #84cc16;
  --color-latency-fair: #eab308;
  --color-latency-poor: #f97316;
  --color-latency-bad: #ef4444;

  /* Spacing */
  --spacing-sidebar: 48px;
  --spacing-sidebar-expanded: 200px;
  --spacing-content: 20px;
  --spacing-card-gap: 12px;
  --spacing-connect-bar: 0px;

  /* Radius */
  --radius-card: 8px;
  --radius-button: 6px;
  --radius-input: 6px;
  --radius-sm: 4px;
}
```

Note: `--color-accent-cyan`, `--color-accent-purple`, `--color-accent-lime`, and `--color-accent-lime-soft-10` are deliberately removed. They'll show up as referenced tokens in other components — those usages are fixed in Tasks 4, 5, and 6.

Leave the `@keyframes`, `body`, `.mono`, `.hairline-divider`, scrollbar, and tauri-drag-region rules as-is for now.

- [ ] **Step 2: Run tests**

```bash
cd swifttunnel-app/swifttunnel-desktop && bun run test
```

Expected: all pass. (Tests don't assert on colors.)

- [ ] **Step 3: Preview sanity check**

Start/refresh preview, load Connect tab. The app will look partially broken (gradient sidebar brand, purple tester pill, etc. reference removed tokens — they'll fall back to transparent) but should not crash. Use `preview_console_logs` to confirm no JS errors.

- [ ] **Step 4: Commit**

```bash
git add src/styles/globals.css
git commit -m "feat(ui): replace color tokens with black & white palette"
```

---

### Task 2: Add swift.png brand asset and regenerate app icons

**Files:**
- Create: `swifttunnel-desktop/public/swift.png` (copied from source)
- Create: `swifttunnel-desktop/src/assets/swift.png` (copied from source, for React imports)
- Replace: `swifttunnel-desktop/src-tauri/icons/icon.ico`
- Replace: `swifttunnel-desktop/src-tauri/icons/icon.png`
- Modify: `swifttunnel-desktop/index.html` (favicon link)

- [ ] **Step 1: Copy source PNG into the repo**

```bash
cd swifttunnel-app/swifttunnel-desktop
mkdir -p src/assets
cp /Users/Evelyn/Downloads/swift.png public/swift.png
cp /Users/Evelyn/Downloads/swift.png src/assets/swift.png
```

- [ ] **Step 2: Regenerate Windows icon set**

```bash
cd swifttunnel-app/swifttunnel-desktop
bunx @tauri-apps/cli icon public/swift.png --output src-tauri/icons
```

This overwrites `src-tauri/icons/icon.ico` and `icon.png` and populates any size variants Tauri needs. Verify the two files exist and are newer than before (`ls -la src-tauri/icons`).

- [ ] **Step 3: Update favicon in index.html**

Open `swifttunnel-desktop/index.html`. Find the existing `<link rel="icon" ...>` and change the `href` to `/swift.png`. If no favicon link exists, add inside `<head>`:

```html
<link rel="icon" type="image/png" href="/swift.png" />
```

- [ ] **Step 4: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 5: Preview check**

Reload preview via `preview_eval: window.location.reload()`. The favicon in the browser tab should be the new swirl logo. Take a `preview_screenshot` to confirm.

- [ ] **Step 6: Commit**

```bash
git add public/swift.png src/assets/swift.png src-tauri/icons/ index.html
git commit -m "feat(ui): add swift.png brand mark and regenerate app icons"
```

---

### Task 3: Switch LiveGraph stroke from green to white

**Files:**
- Modify: `swifttunnel-desktop/src/components/connect/LiveGraph.tsx`

Implements spec §Component language → Throughput graph.

- [ ] **Step 1: Inspect LiveGraph**

Read the file. It currently uses `--color-status-connected` or `--color-latency-excellent` (green) for its stroke and a green glow filter. Find every occurrence of a green token, hardcoded green hex, or `stroke="#28d296"` style value.

- [ ] **Step 2: Replace stroke and glow references**

Swap:
- Line-stroke fill/color → `var(--color-text-primary)` (i.e. `#fafafa`)
- Any glow/filter green hex → `rgba(255, 255, 255, 0.15)`
- Gridline color (if any) → `rgba(255, 255, 255, 0.06)`
- Area fill gradient (if present) → `rgba(255, 255, 255, 0.08)` → `rgba(255, 255, 255, 0)`

Do not rename props or alter logic. Preserve tests.

- [ ] **Step 3: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 4: Preview check**

Reload preview, navigate to Connect. Graph should render as a white line on black background. Take a `preview_screenshot` of the Connect tab.

- [ ] **Step 5: Commit**

```bash
git add src/components/connect/LiveGraph.tsx
git commit -m "feat(ui): render live throughput graph in monochrome white"
```

---

### Task 4: Restyle UI primitives Part 1 — Button, Card, Toggle, Chip, Segmented, Slider

**Files:**
- Modify: `swifttunnel-desktop/src/components/ui/Button.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Card.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Toggle.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Chip.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Segmented.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Slider.tsx`
- Modify: `swifttunnel-desktop/src/styles/globals.css` (slider thumb focus halo)

Implements spec §Component language (first 6 primitives). Only change styles and the tokens being referenced. Do **not** change prop APIs or behavior — other code consumes them.

- [ ] **Step 1: Button.tsx**

Read the current file. The component already exposes variants (primary / secondary / destructive / ghost). Replace any blue/accent gradient with flat monochrome per spec:

- **Primary**: `background: #ffffff`, `color: #000000`, no shadow, 6px radius. Hover: `background: rgba(255,255,255,0.9)`. Disabled: `background: rgba(255,255,255,0.3); color: rgba(0,0,0,0.5)`.
- **Secondary**: `background: transparent`, `border: 1px solid var(--color-border-default)`, `color: var(--color-text-primary)`. Hover: `border-color: var(--color-border-hover)`, `background: var(--color-bg-hover)`.
- **Destructive**: `background: transparent`, `border: 1px solid var(--color-status-error)`, `color: var(--color-status-error)`. Hover: `background: var(--color-status-error-soft-10)`.
- **Ghost**: `background: transparent`, no border, `color: var(--color-text-secondary)`. Hover: `background: var(--color-bg-hover); color: var(--color-text-primary)`.
- Focus ring on all variants: `outline: 2px solid var(--color-accent-primary-soft-20); outline-offset: 2px`.

Keep the component's prop signature and exported types identical.

- [ ] **Step 2: Card.tsx**

Replace any shadow with nothing. Set `background: var(--color-bg-card)`, `border: 1px solid var(--color-border-default)`, `border-radius: var(--radius-card)`. Remove gradients and hover lift effects. Keep padding props.

- [ ] **Step 3: Toggle.tsx**

Monochrome switch.

- Track (off): `background: var(--color-bg-active)` (i.e. `#242424`)
- Track (on): `background: #ffffff`
- Thumb: always `background: #ffffff` when off → shown as contrast circle within dark track; when on, thumb becomes `background: #000000` against the white track (classic inverted mono look).

If that inversion is awkward in the current implementation, simpler alternative:
- Track (off): `#242424`, Thumb (off): `#6a6a6a`
- Track (on): `#ffffff`, Thumb (on): `#000000`

Pick whichever reads better visually; verify with preview.

Focus ring: `2px solid rgba(255,255,255,0.2)`, offset 2px. Disabled: `opacity: 0.4`.

- [ ] **Step 4: Chip.tsx**

- Default: `background: transparent`, `border: 1px solid var(--color-border-default)`, `color: var(--color-text-primary)`, 999px radius.
- Selected: `border: 1px solid #ffffff`, `background: var(--color-accent-primary-soft-12)`, show a 10px white check glyph before the label.
- Hover (unselected): `border-color: var(--color-border-hover)`.

Remove purple/tester coloring. If a `variant="tester"` path existed using purple, change it to: `border: 1px solid var(--color-text-muted); color: var(--color-text-muted)` (no color branding — it's now a neutral pill).

- [ ] **Step 5: Segmented.tsx**

- Track: `background: var(--color-bg-card)`, `border: 1px solid var(--color-border-default)`, `border-radius: var(--radius-button)`, `padding: 2px`.
- Segment (default): transparent, `color: var(--color-text-secondary)`.
- Segment (selected): `background: var(--color-accent-primary-soft-12)`, `color: var(--color-text-primary)`, with a 1px white underline (`box-shadow: inset 0 -1px 0 #ffffff`) rather than a filled pill.
- Hover (unselected): `color: var(--color-text-primary)`.

- [ ] **Step 6: Slider.tsx and slider CSS**

Update both the React component and `globals.css` sibling rules.

In `globals.css`, replace the `.ui-slider` / `.boost-slider` block with:

```css
.ui-slider,
.boost-slider {
  -webkit-appearance: none;
  appearance: none;
  height: 2px;
  border-radius: 1px;
  outline: none;
  cursor: pointer;
  background: var(--color-bg-active);
}
.ui-slider::-webkit-slider-thumb,
.boost-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #ffffff;
  cursor: pointer;
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.15);
  transition: box-shadow 0.15s ease;
}
.ui-slider::-webkit-slider-thumb:hover,
.boost-slider::-webkit-slider-thumb:hover {
  box-shadow: 0 0 0 4px rgba(255, 255, 255, 0.18);
}
.ui-slider:disabled,
.boost-slider:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
```

In `Slider.tsx`, if the component renders its own filled portion (track-to-thumb fill), change that color to `#ffffff`; gray remainder stays `var(--color-bg-active)`.

- [ ] **Step 7: Run tests**

```bash
bun run test
```

Expected: all pass. Tests assert behavior, not colors, so this should be green.

- [ ] **Step 8: Preview check**

Reload preview. Visit Connect and Boost tabs. Verify:
- Primary buttons are white bg / black text
- Toggles read as mono (no blue)
- Sliders have white thumbs
- Segmented (if present on Boost) has white underline on selected

Take a `preview_screenshot` of Boost tab.

- [ ] **Step 9: Commit**

```bash
git add src/components/ui/Button.tsx src/components/ui/Card.tsx src/components/ui/Toggle.tsx src/components/ui/Chip.tsx src/components/ui/Segmented.tsx src/components/ui/Slider.tsx src/styles/globals.css
git commit -m "feat(ui): restyle core primitives to monochrome language"
```

---

### Task 5: Restyle UI primitives Part 2 — Dialog, Tooltip, ErrorBanner, EmptyState, Spinner, MetricGrid, StatDisplay, Row, SectionHeader

**Files:**
- Modify: `swifttunnel-desktop/src/components/ui/Dialog.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Tooltip.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/ErrorBanner.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/EmptyState.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Spinner.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/MetricGrid.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/StatDisplay.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/Row.tsx`
- Modify: `swifttunnel-desktop/src/components/ui/SectionHeader.tsx`

Implements remaining items in spec §Component language.

- [ ] **Step 1: Dialog.tsx**

- Backdrop: `background: rgba(0, 0, 0, 0.6)`, `backdrop-filter: blur(4px)`.
- Panel: `background: var(--color-bg-elevated)`, `border: 1px solid var(--color-border-default)`, `border-radius: 8px`, `box-shadow: none` (remove drop shadows).
- Title: `font-weight: 600`, `color: var(--color-text-primary)`.
- Close button: use ghost Button variant.

- [ ] **Step 2: Tooltip.tsx**

- `background: var(--color-bg-elevated)`, `border: 1px solid var(--color-border-default)`, `color: var(--color-text-primary)`, 6px radius, `font-size: 11px`. Remove any arrow pointer fill gradients — use solid `var(--color-bg-elevated)`.

- [ ] **Step 3: ErrorBanner.tsx**

- `background: var(--color-status-error-soft-10)`, `border: 1px solid var(--color-status-error-soft-20)`, `color: var(--color-status-error)` for the leading icon and copy, `color: var(--color-text-primary)` for the body text. Dismiss button: ghost variant.

- [ ] **Step 4: EmptyState.tsx**

- Icon (if any) rendered in `var(--color-text-muted)`. Heading `var(--color-text-primary)`. Subtext `var(--color-text-secondary)`. No colored accents.

- [ ] **Step 5: Spinner.tsx**

Replace any accent-blue stroke with `var(--color-text-primary)` on a faint `rgba(255,255,255,0.1)` track.

- [ ] **Step 6: MetricGrid.tsx**

- Grid cell background: `transparent`.
- Value: `color: var(--color-text-primary)`, `font-weight: 500`, `font-family: var(--font-mono)` (apply `.mono` class).
- Label: `color: var(--color-text-muted)`, `font-size: 11px`, `font-weight: 500`, `text-transform: uppercase`, `letter-spacing: 0.08em`.
- Separators between cells: 1px `var(--color-border-subtle)` vertical dividers.

- [ ] **Step 7: StatDisplay.tsx**

Same treatment as MetricGrid cells. Strip colored glow. Caps micro-label above mono number.

- [ ] **Step 8: Row.tsx**

- Default background: `transparent`.
- Hover: `background: var(--color-bg-hover)`.
- Selected (if the component supports it): `background: var(--color-accent-primary-soft-08)`, with a 2px white left border (`box-shadow: inset 2px 0 0 #ffffff`).
- Border-bottom between rows: 1px `var(--color-border-subtle)`.

- [ ] **Step 9: SectionHeader.tsx**

- Heading: `var(--color-text-primary)`, `font-weight: 600`, `font-size: 13px`, caps+letter-spacing if the component has an "overline" variant.
- Subtitle: `var(--color-text-secondary)`, `font-size: 12px`.
- Trailing slot (count pill, action button): keep slot API unchanged.

- [ ] **Step 10: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 11: Preview check**

Reload preview. Navigate to each tab briefly. Take `preview_screenshot` of any dialog you can trigger (Settings → Reset perhaps). Use `preview_console_logs` — confirm no errors.

- [ ] **Step 12: Commit**

```bash
git add src/components/ui/
git commit -m "feat(ui): restyle secondary primitives and data displays to mono"
```

---

### Task 6: Replace Sidebar with collapsible icon rail; remove ConnectBar; rewire AppShell

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/shell/Sidebar.tsx`
- Modify: `swifttunnel-desktop/src/components/shell/AppShell.tsx`
- Delete: `swifttunnel-desktop/src/components/shell/ConnectBar.tsx`
- Modify: `swifttunnel-desktop/src/components/shell/StatusChip.tsx` (simplify — becomes a small dot-only component used in the user tile)
- Touch: any test files that import `ConnectBar`

Implements spec §Shell / Navigation.

- [ ] **Step 1: Rewrite Sidebar.tsx**

Replace the entire file contents with:

```tsx
import { useState } from "react";
import { Activity, Settings as SettingsIcon, Zap, Wifi } from "lucide-react";
import { useAuthStore } from "../../stores/authStore";
import { useSettingsStore } from "../../stores/settingsStore";
import { useVpnStore } from "../../stores/vpnStore";
import type { TabId, VpnState } from "../../lib/types";
import { Tooltip } from "../ui/Tooltip";
import swiftLogo from "../../assets/swift.png";

declare const __APP_VERSION__: string;

const TABS: { id: TabId; label: string; shortcut: string; Icon: typeof Wifi }[] = [
  { id: "connect", label: "Connect", shortcut: "1", Icon: Wifi },
  { id: "boost", label: "Boost", shortcut: "2", Icon: Zap },
  { id: "network", label: "Diagnostics", shortcut: "3", Icon: Activity },
  { id: "settings", label: "Settings", shortcut: "4", Icon: SettingsIcon },
];

function dotColor(state: VpnState): string {
  if (state === "connected") return "var(--color-status-connected)";
  if (state === "error") return "var(--color-status-error)";
  if (state === "disconnected") return "var(--color-status-inactive)";
  return "var(--color-status-warning)";
}

export function Sidebar() {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const setTab = useSettingsStore((s) => s.setTab);
  const vpnState = useVpnStore((s) => s.state);
  const email = useAuthStore((s) => s.email);
  const [expanded, setExpanded] = useState(false);

  const initial = email?.[0]?.toUpperCase() || "?";
  const userLabel = email ? email.split("@")[0] : "Not signed in";
  const isTransitioning =
    vpnState !== "connected" &&
    vpnState !== "disconnected" &&
    vpnState !== "error";

  return (
    <nav
      data-tauri-drag-region
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
      className="relative flex h-full shrink-0 flex-col overflow-hidden border-r"
      style={{
        width: expanded
          ? "var(--spacing-sidebar-expanded)"
          : "var(--spacing-sidebar)",
        backgroundColor: "var(--color-bg-sidebar)",
        borderColor: "var(--color-border-subtle)",
        transition: "width 0.12s ease",
      }}
    >
      {/* Brand */}
      <div
        className="flex items-center gap-2.5 px-3 pt-4 pb-4"
        data-tauri-drag-region
      >
        <img
          src={swiftLogo}
          alt="SwiftTunnel"
          width={28}
          height={28}
          className="shrink-0"
          style={{ objectFit: "contain" }}
        />
        {expanded && (
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold leading-none tracking-[-0.01em] text-text-primary">
              SwiftTunnel
            </div>
            <div className="mt-1 font-mono text-[10px] leading-none text-text-dimmed">
              v{__APP_VERSION__}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="mt-2 flex flex-1 flex-col gap-0.5 px-2">
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id;
          const button = (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              className="group relative flex h-9 items-center gap-3 rounded-[5px] px-2 text-left transition-colors duration-100"
              style={{
                backgroundColor: isActive
                  ? "var(--color-accent-primary-soft-12)"
                  : "transparent",
              }}
              aria-label={tab.label}
              aria-current={isActive ? "page" : undefined}
            >
              {isActive && (
                <span
                  className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2"
                  style={{ backgroundColor: "#ffffff" }}
                />
              )}
              <tab.Icon
                size={18}
                strokeWidth={1.8}
                color={
                  isActive
                    ? "var(--color-text-primary)"
                    : "var(--color-text-muted)"
                }
                style={{ flexShrink: 0, marginLeft: 2 }}
              />
              {expanded && (
                <>
                  <span
                    className="flex-1 text-[13px] font-medium"
                    style={{
                      color: isActive
                        ? "var(--color-text-primary)"
                        : "var(--color-text-secondary)",
                    }}
                  >
                    {tab.label}
                  </span>
                  <span
                    className="font-mono text-[10px]"
                    style={{ color: "var(--color-text-dimmed)" }}
                  >
                    ⌃{tab.shortcut}
                  </span>
                </>
              )}
            </button>
          );

          return expanded ? (
            button
          ) : (
            <Tooltip
              key={tab.id}
              content={`${tab.label}  ·  ⌃${tab.shortcut}`}
              side="right"
              delay={200}
            >
              {button}
            </Tooltip>
          );
        })}
      </div>

      {/* User tile */}
      <div className="p-2">
        <div
          className="flex h-9 items-center gap-2.5 rounded-[5px] px-2"
          style={{
            backgroundColor: "transparent",
          }}
        >
          <div className="relative shrink-0">
            <div
              className="flex h-7 w-7 items-center justify-center rounded-full text-[11px] font-semibold"
              style={{
                backgroundColor: "var(--color-bg-hover)",
                color: "var(--color-text-primary)",
                border: "1px solid var(--color-border-default)",
              }}
            >
              {initial}
            </div>
            <span
              className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full"
              style={{
                backgroundColor: dotColor(vpnState),
                border: "2px solid var(--color-bg-sidebar)",
                animation: isTransitioning
                  ? "pulse-opacity 1.2s ease-in-out infinite"
                  : "none",
              }}
              aria-label={`VPN ${vpnState}`}
            />
          </div>
          {expanded && (
            <div className="min-w-0 flex-1 leading-none">
              <div className="truncate text-[12px] font-medium text-text-primary">
                {userLabel}
              </div>
              <div
                className="mt-1 text-[10px] font-medium uppercase tracking-[0.08em]"
                style={{ color: "var(--color-text-muted)" }}
              >
                {vpnState === "connected" ? "Tunneled" : "Idle"}
              </div>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
```

- [ ] **Step 2: Update AppShell.tsx**

Remove the `ConnectBar` import and its usage. Replace the entire file with:

```tsx
import { useEffect, useRef, type ReactNode } from "react";
import { motion } from "framer-motion";
import { useSettingsStore } from "../../stores/settingsStore";
import { Sidebar } from "./Sidebar";
import { BindingChooserDialog } from "./BindingChooserDialog";
import { ToastContainer } from "../common/Toast";

interface AppShellProps {
  children: (activeTab: string) => ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const activeTab = useSettingsStore((s) => s.activeTab);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, 0);
  }, [activeTab]);

  return (
    <>
      <div className="flex h-screen w-screen overflow-hidden">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto"
            style={{
              paddingLeft: "var(--spacing-content)",
              paddingRight: "var(--spacing-content)",
              paddingTop: "var(--spacing-content)",
              paddingBottom: "var(--spacing-content)",
            }}
          >
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
            >
              {children(activeTab)}
            </motion.div>
          </div>
        </div>
      </div>
      <ToastContainer />
      <BindingChooserDialog />
    </>
  );
}
```

- [ ] **Step 3: Delete ConnectBar.tsx**

```bash
rm swifttunnel-desktop/src/components/shell/ConnectBar.tsx
```

- [ ] **Step 4: Simplify StatusChip.tsx**

The Connect screen (Task 7) still wants a status pill in the hero. Keep the component, but restyle to minimalist mono:

- `display: inline-flex`, `gap: 6px`, `padding: 4px 10px`, `border-radius: 999px`.
- `background: transparent`, `border: 1px solid var(--color-border-default)`.
- Leading 6px dot colored via existing `dotColor` helper (keep current logic).
- Label: `color: var(--color-text-secondary)`, `font-size: 11px`, `font-weight: 500`, `text-transform: uppercase`, `letter-spacing: 0.08em`.

If StatusChip is no longer imported anywhere after this task, keep it — Task 7 will import it. Do **not** delete.

- [ ] **Step 5: Fix broken imports**

Run a grep and patch any file that still imports `ConnectBar`:

```bash
grep -rn "ConnectBar" swifttunnel-desktop/src || true
```

If any matches (other than the now-deleted file), remove those imports and their usages. Also check tests:

```bash
grep -rn "ConnectBar" swifttunnel-desktop/src/**/*.test.* || true
```

Delete any test that tests behavior exclusive to the removed ConnectBar (e.g. `ConnectBar.*.test.ts`), since the component no longer exists. Connect/disconnect logic lives in `vpnStore` (already tested there) and will get a new UI surface in Task 7.

- [ ] **Step 6: Run tests**

```bash
bun run test
```

Expected: all pass. If any Sidebar-specific test fails because old DOM structure assumptions (e.g. looking for "Menu" label or a specific icon path), update the test to target the new structure (tab buttons by `aria-label`). Do not skip tests — update them.

- [ ] **Step 7: Preview check**

Reload preview. Rail should show:
- `swift.png` logo top-left, 28×28
- 4 icon buttons (Wifi, Zap, Activity, Settings)
- Small user-tile at bottom with avatar + status dot

Hover over the rail — it should expand to ~200px over 120ms showing labels. Mouse-away collapses. Take `preview_screenshot` of both states (use `preview_eval` with a hover simulation or just hover manually via preview click).

- [ ] **Step 8: Commit**

```bash
git add src/components/shell/ src/styles/globals.css
git rm src/components/shell/ConnectBar.tsx 2>/dev/null || true
git commit -m "feat(ui): replace sidebar with collapsible icon rail and remove ConnectBar"
```

---

### Task 7: Redesign Connect screen

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/connect/ConnectTab.tsx`
- Possibly update: `swifttunnel-desktop/src/components/connect/ConnectTab.icon.test.ts` (adjust to new DOM if needed)
- Possibly update: `swifttunnel-desktop/src/components/connect/connect.css` (prune unused rules)

Implements spec §Screens → Connect.

Because the current ConnectTab is large and specific to the old layout, this is a full rewrite. Keep all store subscriptions and behavioral wiring (region selection, target toggling, connect/disconnect). Replace the layout only.

- [ ] **Step 1: Read current ConnectTab and extract behavioral hooks**

Read `src/components/connect/ConnectTab.tsx`. Note all store selectors it uses (`useVpnStore`, `useServerStore`, `useSettingsStore`, `useBoostStore` etc.), commands it calls (`connect()`, `disconnect()`, `setActiveRegion`, `toggleTarget`, etc.), and which helpers/components it composes (`LiveGraph`, `StatusChip`, `MetricGrid`, `Chip`, region rows, Auto Route row). Write the new file around the same data bindings.

- [ ] **Step 2: Rewrite ConnectTab.tsx**

Structure (top to bottom):

```tsx
// High-level JSX skeleton — fill in with real store selectors from Step 1
<div className="flex flex-col gap-5">
  {/* Hero */}
  <section className="flex items-start justify-between gap-4">
    <div>
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-text-muted">
        {isConnected ? "Tunneled to" : "Ready to tunnel"}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <span className="text-[20px]">{flagEmoji}</span>
        <span className="text-[22px] font-semibold tracking-[-0.015em] text-text-primary">
          {regionName}
        </span>
        <span className="font-mono text-[14px] text-text-muted">
          {serverId}
        </span>
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="font-mono text-[32px] font-medium text-text-primary tabular-nums">
          {latencyMs}
        </span>
        <span className="text-[13px] text-text-muted">ms</span>
      </div>
    </div>
    <div className="flex flex-col items-end gap-2">
      <StatusChip state={vpnState} />
      <Button
        variant={isConnected ? "destructive" : "primary"}
        onClick={isConnected ? disconnect : connect}
      >
        {isConnected ? "Disconnect" : "Connect"}
      </Button>
    </div>
  </section>

  {/* Throughput */}
  <section>
    <div className="mb-2 flex items-center justify-between">
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-text-muted">
        Throughput · live
      </div>
      <div className="font-mono text-[11px] text-text-muted">
        peak {peakLabel}
      </div>
    </div>
    <LiveGraph /* existing props */ />
  </section>

  {/* Metrics row */}
  <MetricGrid
    items={[
      { label: "Upload", value: uploadStr },
      { label: "Download", value: downloadStr },
      { label: "Session", value: sessionStr },
      { label: "Processes", value: processCountStr },
    ]}
  />

  {/* Targets */}
  <section>
    <SectionHeader
      title="Targets"
      trailing={
        <span className="text-[11px] font-mono text-text-muted">
          {enabledTargets}/{totalTargets}
        </span>
      }
    />
    <div className="mt-3 flex flex-wrap gap-2">
      {targets.map((t) => (
        <Chip
          key={t.id}
          selected={t.enabled}
          onClick={() => toggleTarget(t.id)}
        >
          {t.name}
        </Chip>
      ))}
    </div>
  </section>

  {/* Regions table */}
  <section>
    <SectionHeader
      title="Regions"
      trailing={
        <span className="text-[11px] font-mono text-text-muted">
          {availableCount} available
        </span>
      }
    />
    <div className="mt-3">
      {/* Auto Route row first */}
      <RegionRow
        label="Auto Route"
        subtitle="Picks the fastest relay for every match"
        selected={activeRegion === "auto"}
        onClick={() => selectRegion("auto")}
      />
      {regions.map((r) => (
        <RegionRow
          key={r.id}
          flag={r.flag}
          label={r.name}
          latencyMs={r.latencyMs}
          tier={r.tier}
          selected={activeRegion === r.id}
          onClick={() => selectRegion(r.id)}
        />
      ))}
    </div>
  </section>
</div>
```

Inline a local `RegionRow` component (not a separate file) inside `ConnectTab.tsx`:

```tsx
function RegionRow({
  flag,
  label,
  subtitle,
  latencyMs,
  tier,
  selected,
  onClick,
}: {
  flag?: string;
  label: string;
  subtitle?: string;
  latencyMs?: number;
  tier?: "excellent" | "good" | "fair" | "poor" | "bad";
  selected: boolean;
  onClick: () => void;
}) {
  const tierColor = tier
    ? `var(--color-latency-${tier})`
    : "var(--color-text-muted)";
  return (
    <button
      onClick={onClick}
      className="group flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors"
      style={{
        backgroundColor: selected
          ? "var(--color-accent-primary-soft-8)"
          : "transparent",
        borderBottom: "1px solid var(--color-border-subtle)",
        boxShadow: selected ? "inset 2px 0 0 #ffffff" : "none",
      }}
      onMouseEnter={(e) => {
        if (!selected)
          e.currentTarget.style.backgroundColor = "var(--color-bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected)
          e.currentTarget.style.backgroundColor = "transparent";
      }}
    >
      {flag && <span className="text-[16px]">{flag}</span>}
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-text-primary">
          {label}
        </div>
        {subtitle && (
          <div className="mt-0.5 text-[11px] text-text-muted">{subtitle}</div>
        )}
      </div>
      {typeof latencyMs === "number" && (
        <div className="flex items-center gap-1.5">
          <span
            className="h-1.5 w-1.5 rounded-full"
            style={{ backgroundColor: tierColor }}
          />
          <span className="font-mono text-[12px] tabular-nums text-text-primary">
            {latencyMs}
          </span>
          <span className="text-[10px] text-text-muted">ms</span>
        </div>
      )}
    </button>
  );
}
```

Wire every placeholder in the skeleton to the real store selectors and formatter helpers that the old `ConnectTab.tsx` used — do not re-invent them. Prune any imports you no longer use.

- [ ] **Step 3: Prune connect.css**

Open `src/components/connect/connect.css`. Remove any rules that reference blue/accent glows, the old "LIVE" badge sweep animation, or `.connect-bar-*` classes. Keep anything shared by `LiveGraph`.

- [ ] **Step 4: Update or remove the icon test**

Open `ConnectTab.icon.test.ts`. If it asserts a specific icon/path on the old ConnectBar, rewrite it to assert the hero button's label (`"Connect"` / `"Disconnect"`) via `getByRole("button", { name: /connect|disconnect/i })`. If the test is entirely about the removed ConnectBar icon, delete it.

- [ ] **Step 5: Run tests**

```bash
bun run test
```

Expected: all pass. Fix any test referencing old DOM structure.

- [ ] **Step 6: Preview verification**

Reload preview. On Connect tab:
- Take `preview_screenshot` of disconnected state
- Use `preview_click` on the Connect button → verify state transitions (watch `preview_console_logs`)
- Take another `preview_screenshot` of connected state
- Click a different region → verify selection moves

- [ ] **Step 7: Commit**

```bash
git add src/components/connect/
git commit -m "feat(ui): redesign Connect screen with hero, sparkline, metric row, region table"
```

---

### Task 8: Redesign Boost screen

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/boost/BoostTab.tsx`

Implements spec §Screens → Boost.

- [ ] **Step 1: Read current BoostTab and extract bindings**

Note all `useBoostStore` selectors, validators (from `boostConfig.ts`), and the `apply` command path. Preserve all of that logic.

- [ ] **Step 2: Rewrite layout**

Structure: hairline-divided sections, no cards.

```tsx
<div className="flex flex-col">
  <Group title="FPS mode" subtitle="Base profile for optimizations">
    <Segmented
      options={[
        { value: "balanced", label: "Balanced" },
        { value: "performance", label: "Performance" },
        { value: "ultra", label: "Ultra" },
      ]}
      value={mode}
      onChange={setMode}
    />
  </Group>

  <Group title="Game process" subtitle="Executable to optimize">
    {/* existing input + picker, styled with hairline border */}
  </Group>

  <Group title="Tweaks">
    {tweaks.map((t) => (
      <Row
        key={t.id}
        label={t.label}
        description={t.description}
        trailing={<Toggle checked={t.enabled} onChange={() => toggleTweak(t.id)} />}
      />
    ))}
  </Group>

  <Group title="Advanced" collapsible>
    {/* sliders: polling rate, cpu priority, etc */}
  </Group>

  <div className="sticky bottom-0 mt-6 flex justify-end border-t px-5 py-4"
       style={{ borderColor: "var(--color-border-subtle)", backgroundColor: "var(--color-bg-base)" }}>
    <Button variant="primary" onClick={apply} disabled={!dirty}>
      Apply
    </Button>
  </div>
</div>
```

Define a local `Group` helper in `BoostTab.tsx`:

```tsx
function Group({
  title,
  subtitle,
  children,
  collapsible,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  collapsible?: boolean;
}) {
  const [open, setOpen] = useState(!collapsible);
  return (
    <section
      className="border-t px-1 py-5"
      style={{ borderColor: "var(--color-border-subtle)" }}
    >
      <div
        className="flex items-baseline justify-between"
        onClick={collapsible ? () => setOpen((v) => !v) : undefined}
        style={collapsible ? { cursor: "pointer" } : undefined}
      >
        <div>
          <div className="text-[13px] font-semibold text-text-primary">
            {title}
          </div>
          {subtitle && (
            <div className="mt-0.5 text-[11px] text-text-muted">{subtitle}</div>
          )}
        </div>
        {collapsible && (
          <span className="text-[11px] text-text-muted">
            {open ? "Hide" : "Show"}
          </span>
        )}
      </div>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}
```

Rewire every tweak/slider to its existing store mutation. Do not add or remove tweaks.

- [ ] **Step 3: Run tests**

```bash
bun run test
```

Expected: all pass. Update `BoostTab.windowInput.test.ts` if it queries removed DOM structure — the input itself should still be present.

- [ ] **Step 4: Preview check**

Reload preview, visit Boost tab. Take `preview_screenshot`. Click Segmented options → verify state changes. Toggle a tweak → verify Apply button becomes enabled.

- [ ] **Step 5: Commit**

```bash
git add src/components/boost/
git commit -m "feat(ui): redesign Boost screen with hairline-grouped sections"
```

---

### Task 9: Redesign Diagnostics screen (rename from Network)

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/network/NetworkTab.tsx`
- (No rename of file path needed — the tab id stays `"network"` internally; only the label shown to users is "Diagnostics", which is already the case in Sidebar.)

Implements spec §Screens → Diagnostics.

- [ ] **Step 1: Read current NetworkTab and extract data sources**

Note every store/command it uses to pull network info, VPN info, system info. Preserve bindings.

- [ ] **Step 2: Rewrite as key-value list**

```tsx
<div className="flex flex-col">
  <KvGroup title="Network">
    <KvRow label="Local IP" value={localIp} mono />
    <KvRow label="Gateway" value={gateway} mono />
    <KvRow label="DNS" value={dnsServers.join(", ")} mono />
    <KvRow label="MTU" value={String(mtu)} mono />
  </KvGroup>

  <KvGroup title="VPN">
    <KvRow label="Adapter" value={adapterName} />
    <KvRow label="Session" value={sessionId} mono />
    <KvRow label="Relay" value={relayName} />
    <KvRow label="Protocol" value={protocol} />
  </KvGroup>

  <KvGroup title="System">
    <KvRow label="OS" value={osString} />
    <KvRow label="Driver" value={driverVersion} mono />
    <KvRow label="App" value={appVersion} mono />
  </KvGroup>

  <div className="mt-6 flex gap-2 border-t px-1 pt-5"
       style={{ borderColor: "var(--color-border-subtle)" }}>
    <Button variant="secondary" onClick={runSelfTest}>Run self-test</Button>
    <Button variant="secondary" onClick={exportLogs}>Export logs</Button>
    <Button variant="secondary" onClick={copyDiagnostics}>Copy diagnostics</Button>
  </div>
</div>
```

With helpers defined inline:

```tsx
function KvGroup({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section
      className="border-t px-1 py-5"
      style={{ borderColor: "var(--color-border-subtle)" }}
    >
      <div className="mb-3 text-[11px] font-medium uppercase tracking-[0.08em] text-text-muted">
        {title}
      </div>
      <div>{children}</div>
    </section>
  );
}

function KvRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div
      className="flex items-baseline justify-between py-1.5"
      style={{ borderBottom: "1px solid var(--color-border-subtle)" }}
    >
      <span className="text-[12px] text-text-secondary">{label}</span>
      <span
        className={`text-[12px] text-text-primary ${mono ? "font-mono tabular-nums" : ""}`}
      >
        {value || "—"}
      </span>
    </div>
  );
}
```

If any of the data sources (localIp, gateway, etc.) don't exist in a store yet, fall back to the values the old NetworkTab was already rendering — do not add new data fetches.

- [ ] **Step 3: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 4: Preview check**

Reload preview, visit Diagnostics tab. Take `preview_screenshot`. Verify all rows render, no broken values.

- [ ] **Step 5: Commit**

```bash
git add src/components/network/
git commit -m "feat(ui): redesign Diagnostics screen as hairline key-value list"
```

---

### Task 10: Redesign Settings screen

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/settings/SettingsTab.tsx`

Implements spec §Screens → Settings.

- [ ] **Step 1: Read current SettingsTab**

Enumerate every settings control it currently renders (launch at login, close to tray, minimize to tray, language, notifications, update channel, version display, sign-out button, etc.). Preserve every single one with its current store wiring.

- [ ] **Step 2: Rewrite using `SettingsGroup` + `SettingsRow` helpers**

Reuse the `KvGroup`/`Group` pattern from Tasks 8 and 9 but adapted for settings. Keep it inline in this file to avoid premature abstraction.

```tsx
<div className="flex flex-col">
  <SGroup title="General">
    <SRow label="Launch at login" trailing={<Toggle checked={launchAtLogin} onChange={setLaunchAtLogin} />} />
    <SRow label="Close to tray" trailing={<Toggle checked={closeToTray} onChange={setCloseToTray} />} />
    <SRow label="Minimize to tray" trailing={<Toggle checked={minimizeToTray} onChange={setMinimizeToTray} />} />
  </SGroup>

  <SGroup title="Notifications">
    <SRow label="Connection alerts" trailing={<Toggle checked={notifyConn} onChange={setNotifyConn} />} />
    <SRow label="Update alerts" trailing={<Toggle checked={notifyUpdates} onChange={setNotifyUpdates} />} />
  </SGroup>

  <SGroup title="Updates">
    <SRow label="Current version" trailing={<span className="font-mono text-[12px] text-text-primary">{__APP_VERSION__}</span>} />
    <SRow label="Channel" trailing={<Segmented options={channelOptions} value={channel} onChange={setChannel} />} />
    <SRow label="" trailing={<Button variant="secondary" onClick={checkForUpdates}>Check for updates</Button>} />
  </SGroup>

  <SGroup title="Account">
    <SRow label="Signed in as" trailing={<span className="text-[12px] text-text-primary">{email || "Not signed in"}</span>} />
    <SRow label="" trailing={<Button variant="secondary" onClick={signOut}>Sign out</Button>} />
  </SGroup>

  <SGroup title="Danger zone">
    <SRow
      label="Reset all settings"
      description="Restores defaults for every option on this screen."
      trailing={<Button variant="destructive" onClick={resetSettings}>Reset</Button>}
    />
  </SGroup>
</div>
```

Define `SGroup` and `SRow` locally. `SRow` accepts `label`, optional `description`, and `trailing`. Use `border-bottom: 1px solid var(--color-border-subtle)` between rows.

- [ ] **Step 3: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 4: Preview check**

Reload preview, visit Settings. Take `preview_screenshot`. Toggle two settings; verify store updates via `preview_console_logs`.

- [ ] **Step 5: Commit**

```bash
git add src/components/settings/
git commit -m "feat(ui): redesign Settings screen with grouped hairline rows"
```

---

### Task 11: Redesign Login screen

**Files:**
- Rewrite: `swifttunnel-desktop/src/components/auth/LoginScreen.tsx`

Implements spec §Screens → Login.

- [ ] **Step 1: Read current LoginScreen**

Note the sign-in flow it invokes (`startOAuthFlow` or similar), loading state, error display. Preserve all behavior.

- [ ] **Step 2: Rewrite layout**

```tsx
import swiftLogo from "../../assets/swift.png";

export function LoginScreen() {
  // preserve existing hooks and handlers
  return (
    <div
      className="flex h-screen w-screen items-center justify-center"
      style={{ backgroundColor: "var(--color-bg-base)" }}
      data-tauri-drag-region
    >
      <div className="flex flex-col items-center gap-6">
        <div
          className="flex h-[88px] w-[88px] items-center justify-center rounded-[18px]"
          style={{
            backgroundColor: "var(--color-bg-card)",
            border: "1px solid var(--color-border-default)",
          }}
        >
          <img src={swiftLogo} alt="SwiftTunnel" width={72} height={72} />
        </div>
        <div className="flex flex-col items-center gap-1">
          <div className="text-[22px] font-semibold tracking-[-0.015em] text-text-primary">
            SwiftTunnel
          </div>
          <div className="text-[12px] text-text-muted">
            Low-latency gaming tunnel
          </div>
        </div>
        <div className="mt-2 flex flex-col items-center gap-3">
          <Button variant="primary" onClick={startSignIn} disabled={loading}>
            {loading ? "Opening browser…" : "Sign in with browser"}
          </Button>
          {error && (
            <div className="text-[11px]" style={{ color: "var(--color-status-error)" }}>
              {error}
            </div>
          )}
        </div>
        <div
          className="mt-6 font-mono text-[10px]"
          style={{ color: "var(--color-text-dimmed)" }}
        >
          v{__APP_VERSION__}
        </div>
      </div>
    </div>
  );
}
```

Preserve all `useState`/handler wiring from the original file.

- [ ] **Step 3: Run tests**

```bash
bun run test
```

Expected: all pass.

- [ ] **Step 4: Preview check**

Sign out (or hack `email = null` in devtools via `preview_eval`) to force the login screen. Take `preview_screenshot`.

- [ ] **Step 5: Commit**

```bash
git add src/components/auth/ src/assets/
git commit -m "feat(ui): redesign Login screen with logo hero"
```

---

### Task 12: Update docs and memory

**Files:**
- Modify: `swifttunnel-app/CLAUDE.md` (frontend section, if it describes Sidebar/ConnectBar)
- Modify: `swifttunnel-app/swifttunnel-desktop/CLAUDE.md` if it exists
- Modify: `~/.claude/projects/-Users-Evelyn-Swifttunnel-swifttunnel-app/memory/MEMORY.md` and associated memory files if architecture notes mention ConnectBar or blue theme

Per project rules (root CLAUDE.md): "Never leave documentation out of sync with code."

- [ ] **Step 1: Scan project docs for stale references**

```bash
grep -rn "ConnectBar\|connect-bar\|clean dark pro\|accent-cyan\|accent-purple\|accent-lime\|3c82f6" \
  swifttunnel-app/CLAUDE.md swifttunnel-app/swifttunnel-desktop/CLAUDE.md 2>/dev/null || true
```

Update each hit: rename architecture descriptions to mention "icon rail" (instead of fixed sidebar + ConnectBar), and any color references to "black-and-white theme".

- [ ] **Step 2: Scan memory files**

```bash
grep -rn "ConnectBar\|clean dark pro\|3c82f6\|blue accent" \
  ~/.claude/projects/-Users-Evelyn-Swifttunnel-swifttunnel-app/memory/ 2>/dev/null || true
```

Update any memory entries that describe the UI architecture or theme. Add a short memory note if helpful:

`feedback_ui_theme.md` (or similar) — one-liner noting: "Desktop app uses a strict B&W theme (spec: docs/superpowers/specs/2026-04-25-bw-rebrand-design.md); status colors (green/yellow/red) are preserved."

- [ ] **Step 3: Run tests one more time**

```bash
cd swifttunnel-app/swifttunnel-desktop && bun run test
```

- [ ] **Step 4: Full preview sweep**

Reload preview. Take a `preview_screenshot` of every tab: Connect (disconnected), Connect (connected), Boost, Diagnostics, Settings, Login. Verify visually: no blue accents anywhere, status colors correct, logo visible in rail + login.

- [ ] **Step 5: Commit**

```bash
cd swifttunnel-app
git add CLAUDE.md swifttunnel-desktop/CLAUDE.md 2>/dev/null || true
git commit -m "docs: update frontend docs for B&W rebrand" || echo "no doc changes needed"
```

---

## Final verification

After the last task, before handing back to the user:

- [ ] `cd swifttunnel-app/swifttunnel-desktop && bun test` — all pass
- [ ] `cd swifttunnel-app/swifttunnel-desktop && npm run build` — clean TS compile + vite build
- [ ] Preview screenshots of all five screens captured
- [ ] Branch is `ui-redesign`, commits are in the linear order of tasks above
- [ ] (Per user preference) Testbench smoke test of a full `npm run tauri build` run — only after user confirms they want to go that far

Do **not** merge to `main` or tag a release as part of this plan — those steps are the user's call.
