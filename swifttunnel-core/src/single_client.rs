//! Desktop and Lite must not manage the machine's network state concurrently.

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsIconic, IsWindowVisible, MB_ICONERROR, MB_OK, MessageBoxW, SW_RESTORE,
        SW_SHOW, SetForegroundWindow, ShowWindow,
    };
    use windows::core::{PCWSTR, w};

    struct Reservation(HANDLE);

    impl Drop for Reservation {
        fn drop(&mut self) {
            // SAFETY: this reservation owns the handle returned by CreateMutexW.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn reserve(name: PCWSTR) -> windows::core::Result<Option<Reservation>> {
        // Existence, not thread ownership, is the guard. Keep the new object's
        // handle for the process lifetime; do not wait on an existing object.
        let handle = unsafe { CreateMutexW(None, false, name)? };
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let reservation = Reservation(handle);
        Ok((!existed).then_some(reservation))
    }

    fn reserve_clients(
        global: PCWSTR,
        legacy: PCWSTR,
    ) -> windows::core::Result<Option<Vec<Reservation>>> {
        let Some(machine) = reserve(global)? else {
            return Ok(None);
        };
        // Older Desktop/Lite releases only take this session-local name. Hold
        // it too, so upgrading one build does not allow the other to start.
        let Some(session) = reserve(legacy)? else {
            return Ok(None);
        };
        Ok(Some(vec![machine, session]))
    }

    pub fn acquire() -> bool {
        match reserve_clients(
            w!("Global\\SwiftTunnelSingleClient"),
            w!("SwiftTunnelSingleClient"),
        ) {
            Ok(Some(reservations)) => {
                // Both handles live until process exit, including network cleanup.
                std::mem::forget(reservations);
                true
            }
            Ok(None) => {
                log::info!("another SwiftTunnel client is already running; focusing it");
                focus_running_client();
                false
            }
            Err(error) => {
                log::error!("Could not reserve the single-client lock: {error}");
                let message: Vec<u16> = format!(
                    "SwiftTunnel could not check whether another copy is running. Close other SwiftTunnel windows and try again.\n\nWindows reported: {error}"
                ).encode_utf16().chain(Some(0)).collect();
                unsafe {
                    let _ = MessageBoxW(
                        None,
                        PCWSTR(message.as_ptr()),
                        w!("SwiftTunnel"),
                        MB_OK | MB_ICONERROR,
                    );
                }
                false
            }
        }
    }

    fn focus_running_client() {
        for title in [w!("SwiftTunnel"), w!("SwiftTunnel Lite")] {
            // SAFETY: both strings are static and NUL-terminated. Window calls
            // are best effort; another session's window is not accessible here.
            unsafe {
                let Ok(window) = FindWindowW(None, title) else {
                    continue;
                };
                if window.0.is_null() {
                    continue;
                }
                if IsIconic(window).as_bool() {
                    let _ = ShowWindow(window, SW_RESTORE);
                } else if !IsWindowVisible(window).as_bool() {
                    let _ = ShowWindow(window, SW_SHOW);
                }
                let _ = SetForegroundWindow(window);
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::System::Threading::CreateEventW;

        fn name(global: bool) -> Vec<u16> {
            format!(
                "{}SwiftTunnel-instance-test-{:032x}",
                if global { "Global\\" } else { "" },
                rand::random::<u128>()
            )
            .encode_utf16()
            .chain(Some(0))
            .collect()
        }

        #[test]
        fn machine_reservation_excludes_a_different_session_name_until_released() {
            let machine = name(true);
            let first_session = name(false);
            let second_session = name(false);
            let first = reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(first_session.as_ptr()))
                .unwrap()
                .unwrap();
            assert!(
                reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(second_session.as_ptr()))
                    .unwrap()
                    .is_none()
            );
            drop(first);
            assert!(
                reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(second_session.as_ptr()))
                    .unwrap()
                    .is_some()
            );
        }

        #[test]
        fn legacy_client_prevents_startup_and_does_not_leak_machine_reservation() {
            let machine = name(true);
            let session = name(false);
            let legacy = reserve(PCWSTR(session.as_ptr())).unwrap().unwrap();
            assert!(
                reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(session.as_ptr()))
                    .unwrap()
                    .is_none()
            );
            assert!(reserve(PCWSTR(machine.as_ptr())).unwrap().is_some());
            drop(legacy);
            assert!(
                reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(session.as_ptr()))
                    .unwrap()
                    .is_some()
            );
        }

        #[test]
        fn an_object_type_collision_refuses_startup_and_releases_other_handles() {
            let machine = name(true);
            let session = name(false);
            let event = Reservation(unsafe {
                CreateEventW(None, false, false, PCWSTR(session.as_ptr())).unwrap()
            });
            assert!(reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(session.as_ptr())).is_err());
            assert!(reserve(PCWSTR(machine.as_ptr())).unwrap().is_some());
            drop(event);
            assert!(
                reserve_clients(PCWSTR(machine.as_ptr()), PCWSTR(session.as_ptr()))
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[cfg(windows)]
pub use imp::acquire;

#[cfg(not(windows))]
pub fn acquire() -> bool {
    true
}
