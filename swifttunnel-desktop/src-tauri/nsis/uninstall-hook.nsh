!macro NSIS_HOOK_PREUNINSTALL
    DetailPrint "SwiftTunnel: cleaning up system state..."
    ClearErrors
    StrCpy $1 "$INSTDIR\swifttunnel-desktop.exe"
    IfFileExists "$1" cleanup_binary_found 0
    StrCpy $1 "$INSTDIR\SwiftTunnel.exe"
    IfFileExists "$1" cleanup_binary_found 0
        MessageBox MB_ICONSTOP|MB_OK "SwiftTunnel cleanup executable was not found. Uninstall has been aborted to avoid leaving system changes behind."
        Abort
    cleanup_binary_found:
    ExecWait '"$1" --cleanup' $0
    IfErrors 0 +4
        MessageBox MB_ICONSTOP|MB_OK "SwiftTunnel cleanup failed to start. Uninstall has been aborted to avoid leaving system changes behind."
        Abort
        Goto cleanup_done
    IntCmp $0 0 cleanup_done
        MessageBox MB_ICONSTOP|MB_OK "SwiftTunnel cleanup exited with code $0. Uninstall has been aborted to avoid leaving system changes behind."
        Abort
    cleanup_done:
!macroend
