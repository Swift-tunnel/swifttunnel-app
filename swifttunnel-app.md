# SwiftTunnel Desktop App - Planning Document

**Status**: Planning
**Target Repo**: `github.com/evelynwantscookies-ship-it/swifttunnel-app` (separate, open source)
**License**: MIT or GPL-3.0 (TBD)

---

## Goals

1. **Build Trust** - Open source codebase so users can verify no telemetry/logging
2. **Native Performance** - Low overhead VPN client optimized for gaming
3. **Cross-Platform** - Windows, macOS, Linux support
4. **Stealth Mode** - Phantun integration for restrictive networks

---

## Open Source Strategy

### Why Open Source?
- Users can audit the code (no hidden data collection)
- Community contributions and bug reports
- Builds credibility for a VPN service
- Differentiator from closed-source competitors

### What to Open Source
| Component | Open Source? | Reason |
|-----------|--------------|--------|
| Desktop client | Yes | Full transparency |
| WireGuard integration | Yes | Uses open protocols |
| UI/UX code | Yes | Nothing sensitive |
| Server IPs/keys | No | Keep in web API only |
| Auth tokens | No | Fetched at runtime |

### Security Considerations
- No hardcoded API keys in repo
- Config fetched from swifttunnel.net API after auth
- Private keys generated client-side, never transmitted

---

## Architecture Options

### Option A: Tauri v2 (Recommended)
- **Pros**: Small binary (~10MB), Rust backend, web frontend
- **Cons**: Less mature than Electron
- **WireGuard**: BoringTun (userspace) or native wg

### Option B: Electron
- **Pros**: Mature ecosystem, easy web→desktop
- **Cons**: Large binary (~150MB), higher RAM usage
- **WireGuard**: Child process or native addon

### Option C: Native per-platform
- **Pros**: Best performance, smallest size
- **Cons**: 3x development effort
- **WireGuard**: Native integration

---

## Feature Roadmap

### Phase 1: MVP
- [ ] Login via swifttunnel.net OAuth
- [ ] Fetch VPN config from API
- [ ] Connect/disconnect toggle
- [ ] Server selection (region list)
- [ ] Connection status indicator

### Phase 2: Gaming Features
- [ ] Latency display per server
- [ ] Auto-select best server
- [ ] Split tunneling (Roblox only)
- [ ] Kill switch

### Phase 3: Stealth Mode
- [ ] Phantun client integration
- [ ] Auto-detect blocked networks
- [ ] Fallback to TCP tunneling

### Phase 4: Polish
- [ ] System tray integration
- [ ] Auto-connect on startup
- [ ] Auto-update mechanism
- [ ] Usage statistics (opt-in)

---

## Technical Decisions (TBD)

- [ ] Framework: Tauri vs Electron vs Native
- [ ] WireGuard: BoringTun vs wg-quick vs native
- [ ] Auth: OAuth redirect vs embedded browser
- [ ] Auto-update: Tauri updater vs custom vs app stores
- [ ] Installer: MSI/EXE (Win), DMG (Mac), AppImage/deb (Linux)

---

## Repo Structure (Proposed)

```
swifttunnel-app/
├── README.md              # Setup, build, contribute
├── LICENSE                # MIT or GPL-3.0
├── SECURITY.md            # Security policy
├── CONTRIBUTING.md        # How to contribute
├── src/                   # Frontend (React/Svelte)
├── src-tauri/             # Rust backend (if Tauri)
├── docs/                  # Architecture docs
└── .github/
    ├── workflows/         # CI/CD
    └── ISSUE_TEMPLATE/    # Bug reports, features
```

---

## Notes

- Keep web app and desktop app completely separate
- Desktop app should work offline after initial config fetch
- No sensitive data in the open source repo
- Consider code signing for Windows/macOS ($$$ but builds trust)

---

## Questions to Decide

1. Which framework? (Tauri recommended for size/performance)
2. Which license? (MIT = permissive, GPL = copyleft)
3. Minimum OS versions to support?
4. App store distribution? (Microsoft Store, Mac App Store)
5. Code signing budget?

