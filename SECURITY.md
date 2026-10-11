# Security policy

## Report a vulnerability

Email **support@swifttunnel.net** with the subject "SwiftTunnel security report".
Please report privately before opening a public issue or pull request containing
exploit details. Include:

- The affected component, release version or commit, and Windows version.
- What an attacker needs, what they can do, and reproducible steps.
- A minimal proof of concept and relevant logs with credentials, tickets,
  session identifiers and personal information removed.

Never send passwords, live relay tickets, signing keys or other users' data.
If sensitive evidence is necessary, first ask how to share it privately.
There is currently no published bounty program or guaranteed response deadline.

## Scope and safe testing

Reports about SwiftTunnel-controlled components are welcome, including:

- Desktop and Lite authentication, local storage and process interception.
- The relay protocol, ticket validation, session isolation and destination checks.
- Setup, driver installation, repair, uninstall and privileged helper code.
- Update verification, release workflows and build infrastructure.
- System changes made by the app, including routing, DNS, firewall and optimizer
  settings, and whether they are restored correctly.
- SwiftTunnel website/API authentication and authorization used by the clients.

Use your own accounts, devices and a locally hosted relay for testing. This policy
does not authorize accessing other users' data, exhausting production resources,
attacking third parties, or running a proof of concept on our CI machines. Contact
us before testing that could affect production or other people.

WinpkFilter and Roblox are third-party software. Report integration problems to us;
vulnerabilities in those products themselves also belong with their vendors.
For ordinary connection problems, use support rather than publishing account logs.

## Supported releases and security limits

Use the latest stable release. Security fixes target the current release; older
versions do not have a promised backport schedule. Include an older affected
version in your report if that helps demonstrate a regression.

SwiftTunnel's UDP relay does not add transport encryption or cryptographic
integrity to each packet. Signed tickets authorize relay use; they do not turn the
relay into a privacy VPN. See [V3-ROUTING.md](V3-ROUTING.md) for framing, ticket
validation and remaining on-path risks. Independently encrypted application
traffic stays subject to that application's security guarantees.

There is no published independent security audit. Internal checks, tests and
signed updates are not substitutes for one.

## Release provenance

The release workflow builds tagged commits on GitHub-hosted Windows runners.
The self-hosted tunnel testbench is separate. Its workflow permits main pushes,
manual runs and same-repository PRs; outside PRs are excluded by job conditions.
Workflow edits still need careful review before approval: a job condition in a
PR-editable file is not a sandbox or an organization-level runner access rule.

Releases built with the attestation-enabled workflow generate GitHub build
provenance for the final Desktop/Lite installers, Setup launchers (including
offline variants), update metadata and detached signatures. The action is pinned
to a commit and an attestation failure fails the release job. Verify a downloaded
file using a current GitHub CLI, for example:

```powershell
gh attestation verify .\SwiftTunnel-Setup-VERSION.exe --repo Swift-tunnel/swifttunnel-app --signer-workflow Swift-tunnel/swifttunnel-app/.github/workflows/release.yml
```

Replace `VERSION` with the release version. Check the verified source commit and
ref against the intended release tag and its successful workflow run. Existing
releases, including v3.9.3, are not retroactively attested by this change.
For a manual build, dispatch the workflow at the same release tag as its `tag`
input (`gh workflow run release.yml --ref vVERSION -f tag=vVERSION`). The workflow
rejects a checkout that differs from the triggering commit recorded in provenance.

An attestation links a file digest to a workflow and source revision. It does not
prove bit-for-bit reproducibility, absence of vulnerabilities, or equivalence to
an independent rebuild. The app's existing update signatures remain in use;
provenance does not replace them or provide Windows Authenticode signing.
