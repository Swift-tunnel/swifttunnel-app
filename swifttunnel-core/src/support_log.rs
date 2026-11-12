//! Structured, local milestones for operations that can fail or stall.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Logs static operation and stage names, leaving request data and error
/// bodies out of the support events.
pub struct Operation {
    kind: &'static str,
    id: u64,
    pid: u32,
    started: Instant,
    stage: &'static str,
    stage_started: Instant,
    finished: bool,
}

impl Operation {
    pub fn start(kind: &'static str, stage: &'static str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let now = Instant::now();
        log::info!("[support] op={kind} pid={pid} id={id} event=start stage={stage}");
        Self {
            kind,
            id,
            pid,
            started: now,
            stage,
            stage_started: now,
            finished: false,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn stage(&mut self, next: &'static str) {
        let now = Instant::now();
        log::info!(
            "[support] op={} pid={} id={} event=stage stage={} previous_stage={} previous_stage_ms={}",
            self.kind,
            self.pid,
            self.id,
            next,
            self.stage,
            now.duration_since(self.stage_started).as_millis(),
        );
        self.stage = next;
        self.stage_started = now;
    }

    /// A callback for byte progress that logs at most four lines: the first
    /// byte, then each quarter when the total is known. A download that never
    /// finishes then still shows how far it got and when it last moved.
    pub fn progress_milestones(&self) -> impl FnMut(u64, Option<u64>) + Send + 'static {
        let (kind, pid, id, stage, started) =
            (self.kind, self.pid, self.id, self.stage, self.started);
        let mut next = 0u8;
        move |done, total| {
            let reached = match total {
                _ if done == 0 => return,
                Some(total) if total > 0 => 1 + (done.saturating_mul(4) / total).min(3) as u8,
                _ => 1,
            };
            while next < reached {
                let milestone =
                    ["first_byte", "25_percent", "50_percent", "75_percent"][usize::from(next)];
                next += 1;
                log::info!(
                    "[support] op={kind} pid={pid} id={id} event=progress stage={stage} milestone={milestone} elapsed_ms={}",
                    started.elapsed().as_millis(),
                );
            }
        }
    }

    pub fn check<T, E>(&mut self, result: Result<T, E>) -> Result<T, E> {
        if result.is_err() {
            self.fail("stage_failed");
        }
        result
    }

    /// Like `check`, and also records why the stage failed.
    ///
    /// "stage_failed" alone left an update check that failed ten times in a
    /// row with nothing in the log saying why. Only for stages whose errors
    /// are this app's own wording about updates, installers and files. Never
    /// for sign-in, where an error can carry what the player typed.
    pub fn check_explained<T, E: std::fmt::Display>(
        &mut self,
        result: Result<T, E>,
    ) -> Result<T, E> {
        if let Err(error) = &result {
            if !self.finished {
                log::warn!(
                    "[support] op={} pid={} id={} event=reason stage={} detail=\"{}\"",
                    self.kind,
                    self.pid,
                    self.id,
                    self.stage,
                    bounded_reason(&error.to_string()),
                );
            }
            self.fail("stage_failed");
        }
        result
    }

    pub fn complete(mut self, outcome: &'static str) {
        self.finish(log::Level::Info, outcome);
    }

    /// `complete` for an operation held behind a shared handle.
    pub fn succeed(&mut self, outcome: &'static str) {
        self.finish(log::Level::Info, outcome);
    }

    pub fn fail(&mut self, outcome: &'static str) {
        self.finish(log::Level::Warn, outcome);
    }

    fn finish(&mut self, level: log::Level, outcome: &'static str) {
        if self.finished {
            return;
        }
        self.finished = true;
        let now = Instant::now();
        log::log!(
            level,
            "[support] op={} pid={} id={} event=end stage={} outcome={} stage_ms={} elapsed_ms={}",
            self.kind,
            self.pid,
            self.id,
            self.stage,
            outcome,
            now.duration_since(self.stage_started).as_millis(),
            now.duration_since(self.started).as_millis(),
        );
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        // An uncompleted future may have been cancelled or unwound. Preserve
        // its last stage without guessing which of those happened.
        self.finish(log::Level::Warn, "ended_without_result");
    }
}

/// One short line: no line breaks, no quotes that would end the field, and no
/// query strings, which is where a link carries tokens.
fn bounded_reason(text: &str) -> String {
    const LIMIT: usize = 240;
    let mut reason = String::new();
    for word in text.split_whitespace() {
        let word = match (word.contains("://"), word.find('?')) {
            (true, Some(query)) => &word[..query],
            _ => word,
        };
        if !reason.is_empty() {
            reason.push(' ');
        }
        // Bound the copy before allocating. An error can contain one very
        // long word, such as a malformed version from release metadata.
        let remaining = (LIMIT + 1).saturating_sub(reason.chars().count());
        reason.extend(
            word.chars()
                .take(remaining)
                .map(|ch| if ch == '"' { '\'' } else { ch }),
        );
        if reason.chars().count() >= LIMIT {
            break;
        }
    }
    if reason.chars().count() > LIMIT {
        reason = reason.chars().take(LIMIT).collect();
        reason.push_str("...");
    }
    reason
}

pub fn client_start(edition: &'static str, version: &'static str) {
    log::info!(
        "[support] event=client_start edition={} version={} arch={} pid={}",
        edition,
        version,
        std::env::consts::ARCH,
        std::process::id(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_reason_is_one_bounded_line_without_query_strings() {
        assert_eq!(
            bounded_reason("GitHub releases API returned status 403 Forbidden"),
            "GitHub releases API returned status 403 Forbidden"
        );
        assert_eq!(
            bounded_reason(
                "error sending request for url (https://example.test/a/b?token=secret&x=1):\n  \"timed out\""
            ),
            "error sending request for url (https://example.test/a/b 'timed out'"
        );
        // A question mark in ordinary wording is not a query string.
        assert_eq!(bounded_reason("Is the disk full?"), "Is the disk full?");
        let long = bounded_reason(&"word ".repeat(500));
        assert!(long.chars().count() <= 243 && !long.contains('\n'));

        // Recording a reason must not change the result or end the run twice.
        let mut op = Operation::start("fixture", "download");
        assert_eq!(
            op.check_explained(Err::<(), _>("no route")),
            Err("no route")
        );
        assert_eq!(op.check_explained(Ok::<_, &str>(7)), Ok(7));
        assert!(op.finished);
    }

    #[test]
    fn progress_milestones_are_bounded_and_ignore_empty_reads() {
        let op = Operation::start("fixture", "download");
        let mut progress = op.progress_milestones();
        // None of these may panic or index past the four milestones.
        progress(0, Some(100));
        for done in [1, 30, 30, 60, 99, 100, 500] {
            progress(done, Some(100));
        }
        progress(u64::MAX, Some(1));
        progress(10, None);
        progress(10, Some(0));
        op.complete("done");
    }
}
