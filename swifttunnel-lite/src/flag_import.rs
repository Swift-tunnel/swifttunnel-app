//! One bounded file import, with the draft and revision it was requested for.
//! A size limit cannot make a network or cloud-backed file read responsive.

use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};

use crate::state::RobloxDraft;

#[derive(Debug)]
pub struct ImportedFlags {
    pub text: String,
    pub count: usize,
}

#[derive(Debug)]
struct Job {
    result: Receiver<Result<ImportedFlags, String>>,
    baseline: RobloxDraft,
    revision: u64,
    invalidated: bool,
}

#[derive(Debug, Default)]
pub struct FlagImport {
    job: Option<Job>,
}

fn same_flags(left: &RobloxDraft, right: &RobloxDraft) -> bool {
    left.custom_fflags == right.custom_fflags
        && left.custom_json == right.custom_json
        && left.ultraboost == right.ultraboost
}

impl FlagImport {
    pub fn pending(&self) -> bool {
        self.job.is_some()
    }

    pub fn is_busy(&self) -> bool {
        self.job.as_ref().is_some_and(|job| !job.invalidated)
    }

    pub fn invalidate_after_edit(&mut self, after: &RobloxDraft) {
        if let Some(job) = &mut self.job {
            if !same_flags(&job.baseline, after) {
                job.invalidated = true;
            }
        }
    }

    pub fn start(
        &mut self,
        baseline: RobloxDraft,
        revision: u64,
        read: impl FnOnce() -> Result<ImportedFlags, String> + Send + 'static,
        notify: impl FnOnce() + Send + 'static,
    ) -> Result<(), String> {
        if self.pending() {
            return Err("A file is still being read. Wait before choosing another.".into());
        }
        let (sender, result) = sync_channel(1);
        std::thread::Builder::new()
            .name("lite-flag-import".into())
            .spawn(move || {
                let _ = sender.send(read());
                notify();
            })
            .map_err(|error| {
                log::warn!("Lite flag import worker could not start: {error}");
                "Could not start reading that file. Try again.".to_string()
            })?;
        self.job = Some(Job {
            result,
            baseline,
            revision,
            invalidated: false,
        });
        Ok(())
    }

    pub fn poll(
        &mut self,
        current: &RobloxDraft,
        revision: u64,
    ) -> Option<Result<ImportedFlags, String>> {
        let job = self.job.as_ref()?;
        let result = match job.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => {
                Err("Could not finish reading that file. Try again.".into())
            }
        };
        let job = self.job.take().unwrap();
        (!job.invalidated && job.revision == revision && same_flags(&job.baseline, current))
            .then_some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    use std::sync::mpsc;
    use std::time::Duration;

    fn pending(state: &mut State) -> (mpsc::Sender<()>, mpsc::Receiver<()>) {
        let (release, waiting) = mpsc::channel();
        let (ready, finished) = mpsc::channel();
        state.edit_roblox(|draft| {
            draft.custom_fflags = true;
            draft.custom_json = "old flags".into();
            draft.fflag_ok = true;
        });
        state
            .fflag_import
            .start(
                state.roblox_view(),
                7,
                move || {
                    waiting.recv().unwrap();
                    Ok(ImportedFlags {
                        text: "new flags".into(),
                        count: 1,
                    })
                },
                move || ready.send(()).unwrap(),
            )
            .unwrap();
        (release, finished)
    }

    #[test]
    fn slow_read_is_nonblocking_bounded_and_merges_only_flags() {
        let mut state = State::default();
        let (release, finished) = pending(&mut state);
        state.screen = crate::view::Screen::Roblox;
        state.roblox.installed = true;
        assert!(state.fflag_import.is_busy());
        assert!(matches!(
            crate::screens::footer(&state),
            Some(crate::view::Item::Button { disabled: true, .. })
        ));
        state.finish_flag_import(7);
        assert!(state.fflag_import.pending());
        assert!(
            state
                .fflag_import
                .start(state.roblox_view(), 7, || unreachable!(), || {})
                .is_err()
        );
        state.edit_roblox(|draft| draft.fps_text = "144".into());
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
        state.finish_flag_import(7);
        let draft = state.roblox_view();
        assert_eq!(draft.fps_text, "144");
        assert_eq!(draft.custom_json, "new flags");
        assert!(!state.fflag_import.pending());
    }

    #[test]
    fn newer_flag_intent_or_physical_edit_discards_a_late_read() {
        for invalidate in [true, false] {
            let mut state = State::default();
            let (release, finished) = pending(&mut state);
            if invalidate {
                state.edit_roblox(|draft| draft.custom_fflags = false);
                assert!(!state.fflag_import.is_busy());
                state.edit_roblox(|draft| draft.custom_fflags = true);
            }
            release.send(()).unwrap();
            finished.recv_timeout(Duration::from_secs(2)).unwrap();
            state.finish_flag_import(if invalidate { 7 } else { 8 });
            assert_eq!(state.roblox_view().custom_json, "old flags");
            assert!(!state.fflag_import.pending());
        }
    }

    #[test]
    fn failed_read_keeps_the_previously_valid_payload() {
        let mut state = State::default();
        state.edit_roblox(|draft| {
            draft.custom_fflags = true;
            draft.custom_json = "old flags".into();
            draft.fflag_ok = true;
        });
        let (ready, finished) = mpsc::channel();
        state
            .fflag_import
            .start(
                state.roblox_view(),
                0,
                || Err("Could not read that file.".into()),
                move || ready.send(()).unwrap(),
            )
            .unwrap();
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
        state.finish_flag_import(0);
        let draft = state.roblox_view();
        assert_eq!(draft.custom_json, "old flags");
        assert!(draft.fflag_ok);
        assert_eq!(
            draft.fflag_note.as_deref(),
            Some("File not imported. Could not read that file.")
        );
    }
}
