use tauri::WebviewWindow;

trait WindowOps {
    fn unminimize(&self) -> Result<(), String>;
    fn show(&self) -> Result<(), String>;
    fn set_focus(&self) -> Result<(), String>;
}

impl WindowOps for WebviewWindow {
    fn unminimize(&self) -> Result<(), String> {
        self.unminimize().map_err(|e| e.to_string())
    }

    fn show(&self) -> Result<(), String> {
        self.show().map_err(|e| e.to_string())
    }

    fn set_focus(&self) -> Result<(), String> {
        self.set_focus().map_err(|e| e.to_string())
    }
}

fn restore_window<W: WindowOps>(window: &W) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

pub fn restore_main_window(window: &WebviewWindow) {
    restore_window(window);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockWindow {
        calls: RefCell<Vec<&'static str>>,
        fail_unminimize: bool,
        fail_show: bool,
        fail_focus: bool,
    }

    impl MockWindow {
        fn new(fail_unminimize: bool, fail_show: bool, fail_focus: bool) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_unminimize,
                fail_show,
                fail_focus,
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl WindowOps for MockWindow {
        fn unminimize(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("unminimize");
            if self.fail_unminimize {
                return Err("unminimize failed".to_string());
            }
            Ok(())
        }

        fn show(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("show");
            if self.fail_show {
                return Err("show failed".to_string());
            }
            Ok(())
        }

        fn set_focus(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("set_focus");
            if self.fail_focus {
                return Err("set_focus failed".to_string());
            }
            Ok(())
        }
    }

    #[test]
    fn restore_window_unminimizes_then_shows_and_focuses() {
        let window = MockWindow::new(false, false, false);
        restore_window(&window);
        assert_eq!(window.calls(), vec!["unminimize", "show", "set_focus"]);
    }

    #[test]
    fn restore_window_attempts_all_operations_when_unminimize_fails() {
        let window = MockWindow::new(true, false, false);
        restore_window(&window);
        assert_eq!(window.calls(), vec!["unminimize", "show", "set_focus"]);
    }
}
