!macro NSIS_HOOK_PREUNINSTALL
    DetailPrint "SwiftTunnel: cleaning up system state..."
    ExecWait '"$INSTDIR\SwiftTunnel.exe" --cleanup' $0
    DetailPrint "SwiftTunnel cleanup exited with code $0"
!macroend
