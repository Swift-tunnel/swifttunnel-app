Windows release builds populate this directory from the pinned upstream
GoodbyeDPI release in `.github/workflows/release.yml`.

SwiftTunnel looks for:

- `goodbyedpi.exe`
- `x86_64/goodbyedpi.exe`
- `x86/goodbyedpi.exe`

Keep the matching WinDivert files from the GoodbyeDPI release beside the executable.
Include the upstream GoodbyeDPI and WinDivert license files with the payload.
The helper is launched only with SwiftTunnel's generated Roblox hostlist.
