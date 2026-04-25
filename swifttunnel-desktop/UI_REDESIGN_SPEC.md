# SwiftTunnel Desktop — UI Redesign Spec

> Target: a full rebuild of `src/components/` from a clean foundation.
> Scope: **UI only** — the data layer (stores, commands, events, types) is preserved verbatim.

---

## 0 · Preserve (do not touch)

These layers already work and are wired into Rust/Tauri. The rewrite must re-consume them, not replace them.

### Stores (Zustand, `src/stores/`)
| Store | Key state |
|-------|-----------|
| `authStore` | `state`, `email`, `isTester`, `isLoading`, `error`; actions: `startOAuth`, `pollOAuth`, `cancelOAuth`, `logout`, `refreshProfile`, `fetchState` |
| `vpnStore` | `state` (idle/connecting/connected/error), `region`, `serverEndpoint`, `splitTunnelActive`, `tunneledProcesses`, `bytesUp`, `bytesDown`, `ping`, `connectedAt`, `diagnostics`, `bindingPreflight`, `driverSetupState/Error`; actions: `connect`, `disconnect`, `installDriver`, `fetchThroughput`, `fetchPing`, `fetchState`, `fetchDiagnostics`, `resumeConnectWithAdapter`, `dismissBindingChooser` |
| `settingsStore` | `settings: AppSettings`, `activeTab`, `isLoaded`; actions: `load`, `save`, `update`, `setTab` |
| `serverStore` | `regions`, `servers`, `isLoading`, `error`, latency map; actions: `fetchList`, `fetchLatencies`, `refresh`, `getLatency` |
| `boostStore` | `systemInfo`, `systemMem`, `metrics`, RAM-clean state, admin check, Roblox process state; actions: `fetchSystemInfo`, `fetchSystemMemory`, `fetchMetrics`, `updateConfig`, `cleanRam`, `restartRoblox` |
| `networkStore` | stability/speed/bufferbloat status + result + error; actions: `runStabilityTest`, `runSpeedTest`, `runBufferbloatTest` |
| `updaterStore` | `status` (idle/checking/up_to_date/update_available/installing/error), `availableVersion`, `progressPercent`, `lastChecked`, `error`; actions: `checkForUpdates`, `installUpdate` |
| `toastStore` | `toasts[]`; actions: `addToast`, `dismiss` |

### Tauri commands (`src/lib/commands.ts`)
Auth: `auth_get_state`, `auth_start_oauth`, `auth_poll_oauth`, `auth_cancel_oauth`, `auth_complete_oauth`, `auth_logout`, `auth_refresh_profile`
VPN: `vpn_get_state`, `vpn_preflight_binding`, `vpn_connect`, `vpn_disconnect`, `vpn_get_throughput`, `vpn_get_ping`, `vpn_get_diagnostics`, `vpn_list_network_adapters`
Servers: `server_get_list`, `server_get_latencies`, `server_refresh`, `server_smart_select`
Boost: `boost_get_metrics`, `boost_get_system_memory`, `boost_update_config`, `boost_clean_ram`, `boost_get_system_info`, `boost_restart_roblox`
Network tests: `network_start_stability_test`, `network_start_speed_test`, `network_start_bufferbloat_test`
Settings: `settings_load`, `settings_save`, `settings_generate_network_diagnostics_bundle`
Updater: `updater_check_channel`, `updater_install_channel`
System: `system_is_admin`, `system_check_driver`, `system_install_driver`, `system_launched_from_startup`, `system_open_url`, `system_restart_as_admin`, `system_uninstall`

### Supporting libraries (keep)
- `src/lib/types.ts` — all shared types
- `src/lib/events.ts` — Tauri event listeners
- `src/lib/appBootstrap.ts` — startup sequence
- `src/lib/closeToTray.ts`, `src/lib/windowState.ts` — window lifecycle
- `src/lib/utils.ts`, `src/lib/connectedServer.ts`, `src/lib/regionMatch.ts`, `src/lib/settings.ts`, `src/lib/notifications.ts`, `src/lib/errors.ts`
- `src/components/connect/connectState.ts` — game-preset types + `resolveConnectStatus`
- `src/components/boost/boostConfig.ts` — profile presets + helpers
- `App.tsx` shell (auth gate, effects, keyboard shortcuts, bootstrap, window-state persistence, binding-chooser modal) — keep the effects, replace only the rendered chrome

---

## 1 · Delete and rebuild

Rewrite from scratch:
- `src/components/common/Sidebar.tsx`
- `src/components/common/SectionHeader.tsx`
- `src/components/common/Toggle.tsx`
- `src/components/common/Tooltip.tsx`
- `src/components/common/Toast.tsx`
- `src/components/connect/ConnectTab.tsx` + `connect.css`
- `src/components/boost/BoostTab.tsx`
- `src/components/network/NetworkTab.tsx`
- `src/components/settings/SettingsTab.tsx`
- `src/components/auth/LoginScreen.tsx`
- `src/styles/globals.css` (redesign design tokens; keep existing Tailwind setup)

The `TabContent` render region in `App.tsx` (the `motion.div` wrapping `tabComponent`) is the only part of `App.tsx` that gets re-shaped.

---

## 2 · Feature inventory (exhaustive)

Every affordance currently in the UI. The rebuild must preserve every capability; only the presentation changes.

### 2.1 · App chrome (persistent across all authed tabs)

- **Window controls** — handled by Tauri, but the title bar area must stay `data-tauri-drag-region` so users can drag.
- **Sidebar / tab bar** with 4 sections: Connect, Boost, Network, Settings.
- **Global status chip** — reflects VPN state (Disconnected / Connecting / Connected / Error).
- **User identity footer** — email (or initial), signed-in indicator, tester badge if `isTester`.
- **Version string** — `__APP_VERSION__`, sourced from Vite define.
- **Keyboard shortcuts** — Ctrl+1..4 switches tabs (implemented in `App.tsx`, keep).
- **Binding preflight modal** — when `vpnStore.bindingPreflight` is set, show adapter chooser with candidate list; actions `resumeConnectWithAdapter(guid)` / `dismissBindingChooser` (currently in `App.tsx`).
- **Toasts** — `ToastContainer` renders `toastStore.toasts[]` with type=success/warning/error/info.

### 2.2 · Login screen (unauthenticated state)

- Product pitch (3 features): split tunneling, PC optimization, "28 servers, 12 regions".
- **Continue with Browser** CTA → `authStore.startOAuth()`.
- While awaiting: countdown timer (120 s), "Open browser again" link (re-invokes), Cancel.
- Error state display.

### 2.3 · Connect tab

**Connection control**
- Hero connect/disconnect button with 3 states: idle (blue gradient), transitioning (spinner + "wait" cursor), connected (teal gradient + broadcasting rings).
- 1.5 s "checkmark" success animation after connecting.

**Status panel**
- Status dot + label ("Disconnected / Connecting / Connected / Error").
- If connected: selected region name + server endpoint label (`formatConnectedServerLabel`).
- If idle: selected region flag + name + cached latency, OR "Auto Route", OR "No region selected".
- Error / driver-missing inline state with inline **Install Driver** action when `driverSetupState === "missing"`.

**Live telemetry (connected only)**
- Current ping (ms) with color by quality + quality label chip.
- **Live throughput graph** — samples bytesUp + bytesDown every 1 s, EMA-smoothed, scrolls right→left at 60 fps via CSS transform, 60-sample buffer, right-aligned head dot, clip + edge-fade mask, Y-axis auto-scale with 25% headroom and 8 KB/s floor, "Data · Live" header with current rate.
- HUD strip: Server, Split Tunnel (Active/Inactive), Upload total, Download total, Session timer.
- Tunneled processes chips (live list from `tunneledProcesses`).

**Target games**
- Select game presets from `GAMES` list (currently: Roblox, Valorant, Fortnite — extensible).
- Multi-select toggles; selection drives which processes get tunneled.
- Shows count `N / total`.

**Region selection**
- Server list grouped by region (country flag + name + node count).
- Live latency per region (ms + color + quality chip).
- **Auto Route** card at top (picks the best relay per match).
- Per-region server override (gear menu: "Auto" or specific server by IP/host).
- **Whitelist panel** (only when Auto Route active) — toggle regions that should bypass the tunnel.
- "Last used" badge on the previously connected region.
- Last-refreshed affordance: "Refresh" button (disabled while connected).
- Empty / loading / error states with retry.

**Persistence**
- Selection changes are debounced-saved (500 ms) into settings. Saves flushed on unmount.

### 2.4 · Boost tab

**RAM Cleaner**
- Live memory bar (used/total %).
- Stats row: Used, Total, Available, Standby (GB).
- **Clean RAM** button — long-running with stage string ("Flushing modified pages…", "Purging standby list…"), trimmed count, current process name.
- Admin requirement: if not admin, show "Restart as Admin" button.
- Post-clean result banner: Freed / Standby / Modified / Trimmed count / Deep clean = yes/no / warnings count.

**Optimization profile**
- Preset picker: Performance / Balanced / Quality / Custom.
- Changing profile rewrites the draft config; "Custom" appears when any sub-setting diverges.

**Roblox group** (only when game-preset = Roblox or always visible; keep current behavior)
- Unlock FPS (bool) + **Target FPS** slider (30–1000 + "MAX" = 99999; custom-FPS input 30–9999).
- Ultraboost (bool).
- Window resolution (width × height, validated to 800×600 min / 3840×2160 max).
- Launch Fullscreen (bool).

**System group**
- High Priority Mode (bool).
- 0.5ms Timer Resolution (bool).
- MMCSS Gaming Profile (bool).
- Windows Game Mode (bool).

**Network group**
- Disable Nagle (bool).
- Disable Network Throttling (bool).
- Gaming QoS (bool).

**Process Scheduling group**
- High-Performance GPU Binding (bool).
- Prefer Performance Cores (bool).
- Unbind CPU0 (bool).

**Apply bar**
- Sticky bottom bar appears when `draft !== saved`.
- States: "Unsaved changes", window-validation error, "Roblox must restart for changes to apply" (when any Roblox-affecting setting changed and Roblox is running).
- Actions: Discard / Apply / "Restart & Apply" (when restart needed).

### 2.5 · Network tab

- **Run All Tests** button (disabled when any test running).
- Three independent test cards:
  - **Stability** — duration picker 5s / 10s / 30s / 5min. Results: quality label + sample count + Avg/Min/Max ping + jitter + packet-loss bar + ping timeline chart.
  - **Speed** — Download + Upload Mbps cards with directional arrows + server name. No controls.
  - **Bufferbloat** — Grade (A+/A/B/C/D/F) + Idle/Load/Bloat latencies + verbal guidance.
- Each card: Run button, running spinner, result reveal with height-animated expansion.

### 2.6 · Settings tab

**Account**
- Avatar (first letter), email, tester badge (purple), **Log Out**.

**General**
- Run on Startup (bool).
- Auto Reconnect Tunnel (bool).
- Discord Rich Presence (bool).

**Tunnel**
- Adapter Selection: Smart Auto / Manual segmented picker.
- When Manual: adapter dropdown (loaded from `vpnListNetworkAdapters`), sorted by default-route → up → kind priority (ethernet > wifi > ppp > tunnel > loopback) → name. Warn if previously-selected adapter has gone missing.
- When Smart Auto: display current adapter + route source ("Game route" / "Internet fallback" / "Native route table fallback" / "PowerShell fallback" / "Not resolved").
- API Tunneling (bool) — routes TCP from game processes through relay.
- **Adapter Diagnostics** disclosure — State, Adapter, GUID, Selected ifIndex, Resolved ifIndex, Route source, Route target IP, Has route, Manual binding, Cached override, Binding stage, Validation, Binding reason, Packets tunneled/bypassed. Refreshes every 3 s when connected.

**Updates**
- Update Channel: Stable / Live segmented picker.
- Auto Update (bool).
- Version badge (v__APP_VERSION__) + status row (Checking / You're up to date / vX.Y.Z available / Installing vX.Y.Z with progress bar / error + Retry).
- **Check Now** / **Update Now** / **Retry** buttons (context-dependent).
- Last checked timestamp.

**Experimental** (only when `isTester`)
- Practice Mode (bool) + artificial latency slider (0–100 ms, step 5).
- Custom Relay Server (text input, host:port or "auto").

**Support**
- Generate Network Diagnostics Bundle — long-running, opens folder in Explorer on completion, shows saved path.

**About**
- Product line "SwiftTunnel Desktop vX.Y.Z".
- Links: Website, Discord.
- **Uninstall SwiftTunnel** (destructive red button) → `systemUninstall`.

---

## 3 · Information architecture

Keep the 4-tab shell — it's a known model for VPN apps and users expect it. But rethink within each tab:

- **Connect** is the hero. Everything a user does on a gaming session lives here: one button, one region pick, one glance at live health. Everything else must not compete visually.
- **Boost** is a settings cockpit. The user spends minutes here once, then rarely returns. Favor density + progressive disclosure. No hero.
- **Network** is a tool. Run a diagnostic, read the grade, leave. Cards can be expansive because there are only three of them.
- **Settings** is pure forms. Consistency and grouping matter more than flair. The Tunnel section is the most-used slice and should read first after Account.

**Global behavior**
- Sidebar stays fixed; tab content scrolls independently.
- Tab switches use a simple enter-only opacity/translate animation (no AnimatePresence-mode-wait — that caused the bug we just fixed).
- Connect-state color accents (teal) leak into the sidebar status chip and the Connect hero but nowhere else.

---

## 4 · Aesthetic direction — commit

**Concept: "Observation deck."**

SwiftTunnel is a latency-critical real-time systems tool. The aesthetic should feel like monitoring software on a satellite ground station or an HFT trading terminal — technical, precise, high-information-density without being cluttered. Not cozy, not playful, not corporate SaaS.

### Typography
- **Display / UI**: `Söhne` if available, otherwise `Inter Tight` or `Manrope`. Tight, geometric, slightly condensed. Current "Figtree" is acceptable but too friendly — swap.
- **Numeric / mono**: `Berkeley Mono` or `JetBrains Mono`. All telemetry (ping, throughput, byte counts, timestamps, GUIDs, IP:port) uses mono. The existing `Azeret Mono` is fine if we don't want to add a font.
- **No serifs.** No rounded humanist sans. No Figtree headlines.
- **Type scale**: 10 / 11 / 12 / 13 / 15 / 22 / 42 px. Section headers at 10–11 px, uppercase, 0.1 em tracking.

### Color
Keep the current palette — explicit user requirement.

| Token | Value | Role |
|-------|-------|------|
| `--color-accent-primary` | `#3c82f6` | Primary blue — idle hero, selection |
| `--color-accent-secondary` | `#5a9fff` | Lighter blue — text on accent, links |
| `--color-status-connected` | `#28d296` | Teal — connected state, positive metrics |
| `--color-status-warning` | amber | Connecting, bufferbloat fair |
| `--color-status-error` | red | Error, destructive actions |
| `--color-bg-base` | very dark | App background |
| `--color-bg-card` | slightly lighter | Cards |
| `--color-bg-elevated` | one step more | Popovers, inputs |
| `--color-border-subtle` | low-contrast | Hairlines |

**Treatment**:
- Dark only (no light theme).
- Extend the palette with **one signature accent color** for data visualization — suggest `#a0fad9` (a brighter mint) for data graph fills/glows so they stand apart from the teal "connected" state. This is the only new color.
- Backgrounds are nearly black (`#080a0d` or similar). Cards sit +4% lightness. Borders are +8% alpha-on-white. Avoid gradients on cards — solid fills only. Gradients are reserved for hero power button and "Run All Tests" CTA.

### Atmosphere (the "observation deck" details)
- **Subtle grain overlay** over the whole app — 1–2 % opacity noise PNG or CSS noise. Adds texture without looking dirty.
- **Grid lines** on large empty areas (like the Network tab pre-results) — very faint 1 px, 24 px spacing. Sets the control-panel tone.
- **Ambient scan line** on the live data graph — a ~1 s CSS sweep across the plot area. One per graph, not everywhere.
- **Corner brackets** on the hero power button ring — 4 small L-shaped accents at the corners of an invisible bounding square, like HUD reticle marks. Barely there. Rotate when connecting.
- **Mono timestamps everywhere**. "Last checked 12:34:56" reads as a numeric badge, not a sentence.

### Motion
- Framer Motion remains available.
- **Ambient loops only where the state is live** — breathing glow on the connect ring, pulsing head-dot on the data graph, scan line. Everything else is static.
- **Tab change**: 180 ms opacity + 6 px translate-up, enter-only (no exit animation, no `mode="wait"`).
- **Button presses**: `whileTap: scale 0.97`, spring.
- **Result reveal** (network tests): height auto animation, 250 ms.
- **Never stagger rows** inside lists — it reads as AI slop. Staggered reveals are reserved for ≤ 5 cards at a time (region grid is borderline — keep the stagger short, 20 ms/card, max).

### Iconography
- **Single stroke family** — consistent 1.75 px stroke, round caps, round joins, no fills except logos.
- Replace lucide-style icons with Phosphor's **Duotone** variant only for status indicators (connected/disconnected dots, update status), regular line for everything else.
- **Brand logos** (game targets): inline SVG for Roblox/Valorant/Fortnite — already replaced earlier, keep those paths.

### Component language
- **Cards** — square-ish, 8 px radius. No drop shadow. Border only.
- **Buttons** — 6 px radius, no gradient except primary CTA and hero.
- **Inputs** — borderless by default; border appears on focus.
- **Toggles** — custom, 32 × 18 px, blue knob when on.
- **Segmented picker** — flat, 4 px radius, active segment is filled accent.
- **Toast** — bottom-right, 6 px radius, colored left border strip (success/warn/error).
- **Divider** between sections: 1 px, subtle; OR 24 px negative space (no line). Pick one and stick with it.

---

## 5 · Component primitives to build

Before rebuilding tabs, rebuild primitives so every tab composes from the same kit.

```
src/components/ui/
├── Button.tsx           — variants: primary, secondary, ghost, destructive; sizes sm/md
├── IconButton.tsx       — square, tooltip built-in
├── Toggle.tsx           — animated thumb
├── Segmented.tsx        — string or {value,label}[] options
├── Slider.tsx           — with optional numeric input sibling
├── Card.tsx             — padding variants, optional header slot
├── SectionHeader.tsx    — uppercase label + optional tag + optional right action
├── Row.tsx              — label + desc + trailing control (used in settings/boost)
├── Tooltip.tsx          — Radix primitive, styled
├── Popover.tsx          — for region server override menu, dropdowns
├── Dialog.tsx           — for binding-chooser, uninstall confirm
├── Chip.tsx             — colored quality/grade pills
├── Spinner.tsx          — one size, one style
├── StatDisplay.tsx      — label + mono value + optional unit + optional color
├── MetricGrid.tsx       — 2/3/4 col responsive
├── EmptyState.tsx       — icon + title + desc + optional retry
├── ErrorBanner.tsx      — inline red banner with optional action
├── GrainOverlay.tsx     — the app-wide noise texture layer
└── LiveGraph.tsx        — the 60fps CSS-transform SVG graph, generalized (no business logic)
```

And a root shell:
```
src/components/shell/
├── AppShell.tsx         — sidebar + content region layout
├── Sidebar.tsx          — tab nav, status chip, user footer
├── StatusChip.tsx       — connected/disconnected/connecting
├── DraggableTitleBar.tsx — data-tauri-drag-region spacer
├── BindingChooserDialog.tsx
└── ToastContainer.tsx
```

Tabs become compositions of these primitives. No tab should contain raw styled divs beyond layout scaffolding.

---

## 6 · Build order

Ship in six merge-safe phases. Each phase leaves the app functional.

1. **Tokens + primitives** — rewrite `globals.css` design tokens + build `src/components/ui/*`. Visual regression expected but app still renders.
2. **Shell** — Sidebar + AppShell + StatusChip + binding dialog + toasts. Sidebar replaces current sidebar. Tab content remains the old components.
3. **Connect tab** — full rewrite. Re-use the `LiveGraph` primitive for the throughput graph. Verify connect → disconnect flow in the running app.
4. **Boost tab** — full rewrite. Verify draft/apply + admin elevation + Roblox restart gating.
5. **Network tab** — full rewrite. Verify all 3 tests run.
6. **Settings tab + Login screen** — full rewrite. Verify OAuth loop + adapter selection + updater + uninstall confirm.

At each phase: test in the Vite dev preview with the tauri-mock, then on the Windows testbench VM per the repo's standing rule.

---

## 7 · What "done" looks like

- All features in §2 work, verified click-by-click.
- Zero AnimatePresence `mode="wait"` in the codebase.
- No `max-w-[660px]` or centering constraints on tab content — tabs use the full width.
- No emoji used as UI content (flags for countries are OK, they're data).
- All telemetry values (ping, bytes, timestamps, GUIDs, IP:ports) rendered in mono.
- Every interactive surface has a hover state, a disabled state, and a visible focus ring.
- Tab switching cannot strand a previous tab's content on screen (the bug we hit).
- `npm run test` passes (existing Vitest suites for stores must not regress).
- Dev preview matches a Windows testbench build (font fallbacks pick Segoe UI if custom fonts absent).

---

## 8 · Open design questions (decide before build)

1. **Font licensing** — Söhne is paid. Fall back to Inter Tight or keep Figtree? *(Pick one.)*
2. **Live graph scope** — extend to show upload vs download as two lines, or keep combined total as today? *(Two lines is more technical/"observation deck", more code.)*
3. **Grain overlay** — real PNG asset or CSS `filter: url(#noise)`? *(PNG is faster.)*
4. **Phosphor icons dependency** — adds ~30 KB gz. Worth it, or keep hand-rolled inline SVGs? *(Current inline approach is fine; Phosphor adds consistency.)*
5. **Region card density** — 3 cols (current) vs responsive 4 cols on wider windows. *(App has resizable window, so responsive makes sense.)*
