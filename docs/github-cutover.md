# GitHub Release Cutover

## Goals

- GitHub is the canonical release source.
- GitLab remains a read-only mirror for branches and tags.
- Current installs that already trust the current Tauri updater key keep updating.
- Legacy GitHub installs that still trust the older Tauri updater key move to the current key through a staged bridge.

## Verified Key State

On March 14, 2026, GitHub Actions verified that the updater trust roots are different:

- GitHub release `v1.20.18` verifies with the updater key id `A943D352BDA748D5`.
- GitLab release `1.21.16` is signed by updater key id `436B4C95C608A09A`.

That means the key rotation is real. The current GitHub repo secret `TAURI_UPDATER_PUBLIC_KEY` still corresponds to the legacy GitHub key, not the GitLab-era current key.

## Required Secrets

### GitHub release workflow

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `TAURI_UPDATER_PUBLIC_KEY`
- `TAURI_SIGNING_LEGACY_PRIVATE_KEY` (required only for a legacy bridge tag)
- `TAURI_SIGNING_LEGACY_PRIVATE_KEY_PASSWORD` (required only for a legacy bridge tag)
- `TAURI_UPDATER_LEGACY_PUBLIC_KEY` (required only for a legacy bridge tag, and used as the fallback trust root inside the app)
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY`
- `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64`

Before enabling GitHub as the canonical release path:

1. Copy the existing GitHub signing pair into the legacy slots:
   - `TAURI_SIGNING_LEGACY_PRIVATE_KEY`
   - `TAURI_SIGNING_LEGACY_PRIVATE_KEY_PASSWORD`
   - `TAURI_UPDATER_LEGACY_PUBLIC_KEY`
2. Replace the primary slots with the GitLab-era current signing pair:
   - `TAURI_SIGNING_PRIVATE_KEY`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
   - `TAURI_UPDATER_PUBLIC_KEY`

If you skip that swap, GitHub will keep producing legacy-key releases and current GitLab installs will reject them.

### GitLab mirror workflow

- `GITLAB_MIRROR_PUSH_URL`

Recommended format:

```text
https://<username>:<token>@gitlab.com/swifttunnel-group/swifttunnel-app.git
```

Use a GitLab token that can push to the mirror project.

## Important Constraint

The shipped updater code selects the highest semver release in the GitHub releases API before it asks Tauri to verify the release signature. Because of that, a legacy-key population and a current-key population cannot both auto-update from the same GitHub stable feed if the highest stable version is signed by only one of those keys.

That means the migration must be staged.

Bridge tags are controlled by the checked-in [`release-signing.toml`](../release-signing.toml) allowlist. Normal tags use the current signing key automatically. Any stable tag listed under `legacy_bridge.tags` is signed with the legacy Tauri private key instead.

## Safe Migration Sequence

1. Move the existing GitHub secrets into the `*_LEGACY_*` slots and load the GitLab-era keypair into the primary slots.
2. Push `main` to GitHub and enable the GitHub release workflow.
3. Keep GitLab as a mirror only.
4. Add the chosen bridge tag to `release-signing.toml` before cutting that tag.
5. Publish one legacy bridge release on GitHub.
6. The GitHub release workflow signs that bridge tag with the legacy private key, while still embedding the current updater public key into the app.
7. Wait through the bridge window before publishing a higher stable current-key release on GitHub.
8. After the bridge window, publish normal GitHub releases signed with the current key.

## What The Optional Legacy Public Key Does

If `TAURI_UPDATER_LEGACY_PUBLIC_KEY` is present at build time, newly shipped apps can retry updater verification with the legacy Tauri key when the configured key fails signature verification. This does not rescue already shipped legacy builds by itself, but it prevents future trust-root migrations from being one-way.

## Version Consistency

The desktop version must stay aligned between:

- `swifttunnel-desktop/src-tauri/Cargo.toml`
- `swifttunnel-desktop/src-tauri/tauri.conf.json`

GitHub CI now checks this on every push and pull request with `node scripts/check-desktop-version-sync.mjs`, and the release workflow verifies the same check against the pushed tag version before building.
