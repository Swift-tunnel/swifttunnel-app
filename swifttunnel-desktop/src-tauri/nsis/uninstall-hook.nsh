!macro NSIS_HOOK_PREUNINSTALL
    DetailPrint "SwiftTunnel: cleaning up system state..."
    ClearErrors
    ExecWait '"$INSTDIR\SwiftTunnel.exe" --cleanup' $0
    IfErrors 0 +3
        DetailPrint "SwiftTunnel cleanup failed to start (exe may be missing)."
        Goto cleanup_done
    IntCmp $0 0 cleanup_done
        DetailPrint "SwiftTunnel cleanup exited with code $0"
    cleanup_done:
!macroend
