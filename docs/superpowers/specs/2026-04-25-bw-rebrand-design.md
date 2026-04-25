# SwiftTunnel Desktop — Black & White Rebrand

**Status:** Design approved, pending written review
**Branch:** `ui-redesign`
**Scope:** `swifttunnel-desktop/` (Tauri v2 + React frontend)
**Out of scope:** backend crates, relay protocol, web dashboard, marketing site, new features

## Goal

Rebrand the desktop client to a strict black-and-white visual language inspired by
the new logo (`swift.png`). Replace the existing blue-accent "Clean Dark Pro" theme
with a Linear/Vercel-style minimalist B&W system, redesigning the four main screens
(Connect, Boost, Diagnostics, Settings) plus the auth/login screen.

## Design Principles

1. **Pure B&W chrome.** All surfaces, borders, typography, and interactive emphasis
   are black, white, or gray. The blue accent (`#3c82f6`) is retired; white
   (`#ffffff`) takes its place as the emphasis color.
2. **Status colors preserved.** Connected/warning/error signals and latency tiers
   keep functional color (green/amber/red), tuned one notch less saturated so they
   sit naturally against true black. The throughput graph is data viz, not status —
   it goes white.
3. **Minimalist, not expressive.** Flat surfaces, hairline (1px) borders, no
   shadows, no gradients except where status requires a subtle glow. The logo is
   the only expressive element; the chrome stays quiet.
4. **Full redesign of the four main screens.** Information hierarchy, spacing, and
   component treatments are reconsidered — not just a token swap.
5. **Logo as the sole brand element.** `swift.png` becomes the brand mark across
   the app (rail top, login hero, window icon, tray icon, favicon).

## Palette

### Surfaces
| Token | Value | Use |
|---|---|---|
| `--color-bg-base` | `#000000` | Window background, matches logo bg exactly |
| `--color-bg-sidebar` | `#050505` | Icon rail |
| `--color-bg-card` | `#0a0a0a` | Cards, panels |
| `--color-bg-elevated` | `#141414` | Popovers, dialogs, dropdowns |
| `--color-bg-hover` | `#1a1a1a` | Hover states |
| `--color-bg-active` | `#242424` | Pressed/active states |
| `--color-bg-input` | `#0a0a0a` | Form inputs |
| `--color-bg-glass` | `#0e0e0e` | Translucent overlays |

### Text
| Token | Value | Use |
|---|---|---|
| `--color-text-primary` | `#fafafa` | Primary copy, headings, key numbers |
| `--color-text-secondary` | `#a1a1a1` | Labels, metadata |
| `--color-text-muted` | `#6a6a6a` | Captions, disabled labels |
| `--color-text-dimmed` | `#3f3f3f` | Placeholders, deeply de-emphasized |

### Borders
| Token | Value | Use |
|---|---|---|
| `--color-border-subtle` | `#141414` | Barely-visible separators |
| `--color-border-default` | `#1f1f1f` | Card borders, hairline dividers |
| `--color-border-hover` | `#2a2a2a` | Hover border lift |
| `--color-border-focus` | `#ffffff` | Focus ring (pure white) |

### Emphasis (replaces blue)
| Token | Value | Use |
|---|---|---|
| `--color-accent-primary` | `#ffffff` | Selected tab, active row, primary button bg |
| `--color-accent-primary-soft-8` | `rgba(255,255,255,0.08)` | Selection fill |
| `--color-accent-primary-soft-12` | `rgba(255,255,255,0.12)` | Hover fill |
| `--color-accent-primary-soft-20` | `rgba(255,255,255,0.20)` | Focus ring halo |

The `accent-secondary`, `accent-cyan`, `accent-purple`, `accent-lime` tokens are
removed. Any component using them moves to white or to the appropriate status tier.

### Status (preserved, slightly desaturated)
| Token | Old | New | Use |
|---|---|---|---|
| `--color-status-connected` | `#28d296` | `#22c55e` | Tunnel active dot/pill |
| `--color-status-connected-glow` | `#64f0c8` | `#4ade80` | Connected glow |
| `--color-status-warning` | `#f5b428` | `#eab308` | Warnings |
| `--color-status-error` | `#f05a5a` | `#ef4444` | Errors, disconnect button |
| `--color-status-inactive` | `#50505f` | `#525252` | Inactive dot |

### Latency ramp (preserved, slightly desaturated)
| Token | Old | New |
|---|---|---|
| `--color-latency-excellent` | `#28d296` | `#22c55e` |
| `--color-latency-good` | `#82dc3c` | `#84cc16` |
| `--color-latency-fair` | `#f5b428` | `#eab308` |
| `--color-latency-poor` | `#f08c32` | `#f97316` |
| `--color-latency-bad` | `#f05a5a` | `#ef4444` |

## Typography

Keep the existing stacks — Figtree (sans) and Azeret Mono (numerics). Adjust
weight and tracking usage:

- Headings: `600`, `-0.015em` tracking
- Data/key numbers: `500`, mono, tabular nums
- Body: `400`, `-0.008em` tracking
- Caps micro-labels (e.g. `LIVE`, `TUNNELED TO`): `500`, `0.08em` tracking,
  `11px`, `--color-text-muted`

## Shell / Navigation

Replace the current fixed 188px sidebar + persistent ConnectBar with a
**collapsible icon rail**:

- Default width: **48px** (icon-only)
- Expanded width on hover: **200px** (reveals tab labels + brand wordmark)
- Transition: 120ms ease
- Contents, top to bottom:
  - **Brand mark** — `swift.png` rendered at 28×28, top-aligned with 12px padding
  - **4 tab icons** — Connect, Boost, Diagnostics, Settings (Lucide icons, 18px)
  - **Spacer**
  - **User tile + status dot** — avatar 24×24, dot reflects connection state
- Selected tab indicator: 2px white vertical bar on the left edge of the icon, icon
  goes `--color-text-primary`; unselected icons are `--color-text-muted`
- The persistent ConnectBar is **removed**; Connect/Disconnect moves into the
  Connect screen's hero. Status remains visible globally via the user-tile dot.

## Component Language

Flat, hairline-based, monochrome. All components live under
`swifttunnel-desktop/src/components/ui/`.

- **Cards** — `--color-bg-card`, 1px `--color-border-default`, `--radius-card`
  (8px), no shadow.
- **Buttons**
  - Primary: white bg, black text, `--radius-button` (6px)
  - Secondary: transparent bg, 1px `--color-border-default`, text primary
  - Destructive: transparent bg, 1px `--color-status-error`, text
    `--color-status-error`
  - Ghost: transparent, no border, hover fills `--color-bg-hover`
- **Toggle** — monochrome: gray track (`--color-bg-active`), white thumb. No blue.
- **Segmented** — hairline track, selected segment fills `accent-primary-soft-12`
  with a white bottom underline.
- **Slider** — 2px gray rail, 14px white thumb, focus halo is
  `accent-primary-soft-20`.
- **Chip** — hairline border, text primary, optional leading icon; selected
  variant gets white border + `accent-primary-soft-12` fill.
- **Dialog** — `--color-bg-elevated`, 1px hairline, no shadow (pure outline),
  backdrop `rgba(0,0,0,0.6)`.
- **Tooltip** — `--color-bg-elevated`, 1px hairline, 6px radius, 11px text.
- **Throughput graph** — white stroke on black, 0.5px `rgba(255,255,255,0.06)`
  horizontal gridlines, peak label in mono/muted.
- **Latency badge** — 6px colored dot (per tier) + mono `##ms` in text-primary.
- **Hairline divider** — 1px `--color-border-subtle`, full-width, no gradient.

## Screen Redesigns

### 1. Connect (default view)

Vertical stack, full-bleed content area, no persistent ConnectBar.

- **Hero block** (top):
  - Left: status line — `TUNNELED TO` caps micro-label + country flag + region
    name + `sg-3` server id in mono. Below: live latency in big mono
    (`24px`, primary).
  - Right: Connect/Disconnect button (primary white or destructive red) + status
    pill (green dot + `LIVE` / red dot + `OFFLINE`).
- **Throughput sparkline** — full-width white line graph, ~140px tall, shows
  last 60s. Peak label top-right in mono/muted.
- **Metrics row** — 4 stats in a single horizontal row with hairline dividers
  between: Upload, Download, Session, Processes. Caps micro-label above, big mono
  number below.
- **Targets section** — `TARGETS` caps header + count pill (e.g. `2/3`). Horizontal
  chip row of games (Roblox, Valorant, Fortnite), selected ones show white
  border + check glyph.
- **Regions table** — dense table, one row per relay: flag, city, server count,
  latency badge. Selected region has white left border + `accent-primary-soft-08`
  fill. Auto Route pinned at the top as a special row.

### 2. Boost

Grouped settings, no cards — just hairline-divided sections.

- **FPS Mode** — segmented control (Balanced / Performance / Ultra)
- **Game Process** — input + file picker button
- **Tweaks** — list of toggle rows, one per optimization, with short description
  in `--color-text-secondary`
- **Advanced** — collapsible section for sliders (polling rate, CPU priority, etc.)
- **Apply** button docked bottom-right, primary white

### 3. Diagnostics

Key/value list, hairline dividers, no cards.

- **Network** — Local IP, Gateway, DNS, MTU
- **VPN** — Adapter, Session ID, Relay, Protocol
- **System** — OS, Driver Version, App Version
- **Actions** — "Run self-test", "Export logs", "Copy diagnostics" as secondary
  buttons at the bottom

### 4. Settings

Grouped rows, hairline dividers, no cards.

- **General** — Launch at login, Close to tray, Minimize to tray, Language
- **Notifications** — Connect/disconnect alerts, Update alerts
- **Updates** — Current version, Check for updates button, channel selector
- **Account** — signed-in email, Sign out
- **Danger zone** — Reset settings (destructive button)

### 5. Login / Auth

Full-screen hero.

- Centered, vertically balanced
- `swift.png` rendered at 88×88 with a subtle 1px hairline ring
- `SwiftTunnel` wordmark in Figtree 600, below logo
- Small caption below wordmark: `Low-latency gaming tunnel`
- Primary button: `Sign in with browser` (white bg, black text, 8px radius)
- Footer microtext: version + legal links

## Logo Integration

- **Rail top** — 28×28 monochrome render of `swift.png`
- **Login hero** — 88×88
- **Window icon** — regenerate `.ico` + `.png` resources from `swift.png`
  (app is Windows-only, per project conventions)
- **Tray icon** — 16×16 monochrome render
- **Favicon** (dev server) — 32×32

The existing lightning-bolt glyph currently used as the brand mark is removed
everywhere.

## File-Level Changes (high level)

- `swifttunnel-desktop/src/styles/globals.css` — token overhaul per palette above
- `swifttunnel-desktop/src/components/shell/Sidebar.tsx` — rewrite as collapsible
  icon rail
- `swifttunnel-desktop/src/components/shell/AppShell.tsx` — remove ConnectBar,
  adjust layout grid
- `swifttunnel-desktop/src/components/shell/ConnectBar.tsx` — delete
- `swifttunnel-desktop/src/components/shell/StatusChip.tsx` — restyle or fold into
  user-tile dot
- `swifttunnel-desktop/src/components/connect/ConnectTab.tsx` — rebuild hero,
  metrics row, sections per spec above
- `swifttunnel-desktop/src/components/connect/LiveGraph.tsx` — switch green
  stroke to white, grid styling
- `swifttunnel-desktop/src/components/boost/BoostTab.tsx` — restructure into
  hairline-divided groups
- `swifttunnel-desktop/src/components/network/NetworkTab.tsx` — rewrite as key/
  value list (+ rename header to "Diagnostics")
- `swifttunnel-desktop/src/components/settings/SettingsTab.tsx` — regroup rows
- `swifttunnel-desktop/src/components/auth/LoginScreen.tsx` — logo hero redesign
- `swifttunnel-desktop/src/components/ui/*` — restyle Toggle, Segmented, Slider,
  Chip, Button, Card, Dialog, Tooltip, MetricGrid, StatDisplay for mono language
- `swifttunnel-desktop/src-tauri/icons/*` — regenerate from `swift.png`
- `swifttunnel-desktop/src-tauri/tauri.conf.json` — wire new icon paths if names
  change
- `swifttunnel-desktop/index.html` — favicon swap

## Non-Goals

- No changes to Rust backend, Tauri command surface, or store logic
- No changes to relay protocol or web API contracts
- No new features, no settings additions
- No animation beyond the existing 120ms ease transitions (no swirl/motion
  background even though the logo suggests it — kept minimalist on purpose)
- No light mode

## Testing & Verification

- All existing vitest tests must continue to pass (no behavioral changes)
- Manual verification via `npm run tauri:dev` on `localhost:1420` after each
  screen redesign: Connect (connected + disconnected), Boost, Diagnostics,
  Settings, Login
- Testbench VM smoke test before calling the rebrand done (per user pref)

## Risks

- **Status colors against true black** may need per-screen tuning if any tier
  reads too neon; the single-notch desat in the palette is a first pass.
- **Icon rail hover expansion** can feel laggy if contents reflow — expand
  should use `width` transition on the rail container only, not the content.
- **Window icon regen** needs the source PNG at sufficient resolution
  (`swift.png` is 1695×928, good enough for all target sizes).
