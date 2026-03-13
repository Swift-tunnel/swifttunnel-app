# GitHub Release Cutover

## Goals

- GitHub is the canonical release source.
- GitLab remains a read-only mirror for branches and tags.
- Current installs that already trust the current Tauri updater key keep updating.
- Legacy GitHub installs that still trust the older Tauri updater key move to the current key through a staged bridge.

## Required Secrets

### GitHub release workflow

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `TAURI_UPDATER_PUBLIC_KEY`
- `TAURI_UPDATER_LEGACY_PUBLIC_KEY` (optional, used only for staged migration fallback inside the app)
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY`
- `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64`

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

## Safe Migration Sequence

1. Push `main` to GitHub and enable the GitHub release workflow.
2. Keep GitLab as a mirror only.
3. Publish one legacy bridge release on GitHub from the old-key line.
4. Sign that bridge release with the legacy private key so legacy installs can accept it.
5. Embed the current updater public key in that bridge build so the installed bridge app trusts the current key afterward.
6. Wait through the bridge window before publishing a higher stable current-key release on GitHub.
7. After the bridge window, publish normal GitHub releases signed with the current key.

## What The Optional Legacy Public Key Does

If `TAURI_UPDATER_LEGACY_PUBLIC_KEY` is present at build time, newly shipped apps can retry updater verification with the legacy Tauri key when the configured key fails signature verification. This does not rescue already shipped legacy builds by itself, but it prevents future trust-root migrations from being one-way.
