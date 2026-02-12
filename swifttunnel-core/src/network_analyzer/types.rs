//! Network Analyzer Types
//!
//! State structs, enums, and result types for network analysis

use serde::{Deserialize, Serialize};

/// Overall state of the network analyzer
#[derive(Clone, Debug, Default)]
pub struct NetworkAnalyzerState {
    /// Stability test state
    pub stability: StabilityTestState,
    /// Speed test state
    pub speed: SpeedTestState,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STABILITY TEST TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// State of the stability test
#[derive(Clone, Debug)]
pub struct StabilityTestState {
    /// Whether a test is currently running
    pub running: bool,
    /// Progress 0.0 - 1.0
    pub progress: f32,
    /// Ping samples collected so far (in milliseconds)
    pub ping_samples: Vec<Option<u32>>,
    /// Results after test completes
    pub results: Option<StabilityTestResults>,
}

impl Default for StabilityTestState {
    fn default() -> Self {
        Self {
            running: false,
            progress: 0.0,
            ping_samples: Vec::new(),
            results: None,
        }
    }
}

/// Results from a completed stability test
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StabilityTestResults {
    /// Average ping in milliseconds
    pub avg_ping: f32,
    /// Minimum ping in milliseconds
    pub min_ping: u32,
    /// Maximum ping in milliseconds
    pub max_ping: u32,
    /// Jitter (standard deviation) in milliseconds
    pub jitter: f32,
    /// Packet loss percentage (0.0 - 100.0)
    pub packet_loss: f32,
    /// Quality rating based on results
    pub quality: ConnectionQuality,
    /// Number of samples collected
    pub sample_count: usize,
    /// Timestamp when test completed
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Connection quality rating
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionQuality {
    Excellent, // < 30ms avg, < 1% loss, < 5ms jitter
    Good,      // < 50ms avg, < 2% loss, < 10ms jitter
    Fair,      // < 80ms avg, < 5% loss, < 20ms jitter
    Poor,      // < 120ms avg, < 10% loss, < 40ms jitter
    Bad,       // Everything else
}

impl ConnectionQuality {
    /// Determine quality from test metrics
    pub fn from_metrics(avg_ping: f32, packet_loss: f32, jitter: f32) -> Self {
        if avg_ping < 30.0 && packet_loss < 1.0 && jitter < 5.0 {
            ConnectionQuality::Excellent
        } else if avg_ping < 50.0 && packet_loss < 2.0 && jitter < 10.0 {
            ConnectionQuality::Good
        } else if avg_ping < 80.0 && packet_loss < 5.0 && jitter < 20.0 {
            ConnectionQuality::Fair
        } else if avg_ping < 120.0 && packet_loss < 10.0 && jitter < 40.0 {
            ConnectionQuality::Poor
        } else {
            ConnectionQuality::Bad
        }
    }

    /// Get display label
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionQuality::Excellent => "Excellent",
            ConnectionQuality::Good => "Good",
            ConnectionQuality::Fair => "Fair",
            ConnectionQuality::Poor => "Poor",
            ConnectionQuality::Bad => "Bad",
        }
    }

    /// Get emoji for display
    pub fn emoji(&self) -> &'static str {
        match self {
            ConnectionQuality::Excellent => "🟢",
            ConnectionQuality::Good => "🟢",
            ConnectionQuality::Fair => "🟡",
            ConnectionQuality::Poor => "🟠",
            ConnectionQuality::Bad => "🔴",
        }
    }
}

/// Progress update sent during stability test
#[derive(Clone, Debug)]
pub enum StabilityTestProgress {
    /// New ping sample received (Some = success with ms, None = timeout/loss)
    PingSample(Option<u32>),
    /// Test progress update (0.0 - 1.0)
    Progress(f32),
    /// Test completed with results
    Completed(StabilityTestResults),
    /// Test failed with error message
    Error(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SPEED TEST TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// State of the speed test
#[derive(Clone, Debug)]
pub struct SpeedTestState {
    /// Whether a test is currently running
    pub running: bool,
    /// Current phase of the test
    pub phase: SpeedTestPhase,
    /// Download speed in Mbps (during/after test)
    pub download_speed: f32,
    /// Upload speed in Mbps (during/after test)
    pub upload_speed: f32,
    /// Progress 0.0 - 1.0 for current phase
    pub phase_progress: f32,
    /// Results after test completes
    pub results: Option<SpeedTestResults>,
}

impl Default for SpeedTestState {
    fn default() -> Self {
        Self {
            running: false,
            phase: SpeedTestPhase::Idle,
            download_speed: 0.0,
            upload_speed: 0.0,
            phase_progress: 0.0,
            results: None,
        }
    }
}

/// Current phase of the speed test
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeedTestPhase {
    Idle,
    Download,
    Upload,
    Complete,
}

impl SpeedTestPhase {
    pub fn label(&self) -> &'static str {
        match self {
            SpeedTestPhase::Idle => "Ready",
            SpeedTestPhase::Download => "Testing Download",
            SpeedTestPhase::Upload => "Testing Upload",
            SpeedTestPhase::Complete => "Complete",
        }
    }
}

/// Results from a completed speed test
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpeedTestResults {
    /// Download speed in Mbps
    pub download_mbps: f32,
    /// Upload speed in Mbps
    pub upload_mbps: f32,
    /// Server used for test
    pub server: String,
    /// Timestamp when test completed
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Progress update sent during speed test
#[derive(Clone, Debug)]
pub enum SpeedTestProgress {
    /// Download phase started
    DownloadStarted,
    /// Download progress (speed_mbps, progress 0.0-1.0)
    DownloadProgress(f32, f32),
    /// Download completed with final speed
    DownloadComplete(f32),
    /// Upload phase started
    UploadStarted,
    /// Upload progress (speed_mbps, progress 0.0-1.0)
    UploadProgress(f32, f32),
    /// Upload completed with final speed
    UploadComplete(f32),
    /// Full test completed with results
    Completed(SpeedTestResults),
    /// Test failed with error
    Error(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════════

/// Network test results for settings persistence
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkTestResultsCache {
    /// Last stability test results
    pub last_stability: Option<StabilityTestResults>,
    /// Last speed test results
    pub last_speed: Option<SpeedTestResults>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConnectionQuality::from_metrics ──

    #[test]
    fn test_connection_quality_excellent() {
        // All metrics below excellent thresholds
        assert_eq!(
            ConnectionQuality::from_metrics(29.9, 0.9, 4.9),
            ConnectionQuality::Excellent
        );
        assert_eq!(
            ConnectionQuality::from_metrics(0.0, 0.0, 0.0),
            ConnectionQuality::Excellent
        );
    }

    #[test]
    fn test_connection_quality_good() {
        // At excellent boundary -> falls to Good
        assert_eq!(
            ConnectionQuality::from_metrics(30.0, 0.0, 0.0),
            ConnectionQuality::Good
        );
        assert_eq!(
            ConnectionQuality::from_metrics(0.0, 1.0, 0.0),
            ConnectionQuality::Good
        );
        assert_eq!(
            ConnectionQuality::from_metrics(0.0, 0.0, 5.0),
            ConnectionQuality::Good
        );
        // Just below Good thresholds
        assert_eq!(
            ConnectionQuality::from_metrics(49.9, 1.9, 9.9),
            ConnectionQuality::Good
        );
    }

    #[test]
    fn test_connection_quality_fair() {
        assert_eq!(
            ConnectionQuality::from_metrics(50.0, 0.0, 0.0),
            ConnectionQuality::Fair
        );
        assert_eq!(
            ConnectionQuality::from_metrics(79.9, 4.9, 19.9),
            ConnectionQuality::Fair
        );
    }

    #[test]
    fn test_connection_quality_poor() {
        assert_eq!(
            ConnectionQuality::from_metrics(80.0, 0.0, 0.0),
            ConnectionQuality::Poor
        );
        assert_eq!(
            ConnectionQuality::from_metrics(119.9, 9.9, 39.9),
            ConnectionQuality::Poor
        );
    }

    #[test]
    fn test_connection_quality_bad() {
        assert_eq!(
            ConnectionQuality::from_metrics(120.0, 0.0, 0.0),
            ConnectionQuality::Bad
        );
        assert_eq!(
            ConnectionQuality::from_metrics(0.0, 10.0, 0.0),
            ConnectionQuality::Bad
        );
        assert_eq!(
            ConnectionQuality::from_metrics(0.0, 0.0, 40.0),
            ConnectionQuality::Bad
        );
        assert_eq!(
            ConnectionQuality::from_metrics(200.0, 50.0, 100.0),
            ConnectionQuality::Bad
        );
    }

    // ── ConnectionQuality labels and emojis ──

    #[test]
    fn test_connection_quality_labels() {
        assert_eq!(ConnectionQuality::Excellent.label(), "Excellent");
        assert_eq!(ConnectionQuality::Good.label(), "Good");
        assert_eq!(ConnectionQuality::Fair.label(), "Fair");
        assert_eq!(ConnectionQuality::Poor.label(), "Poor");
        assert_eq!(ConnectionQuality::Bad.label(), "Bad");
    }

    #[test]
    fn test_connection_quality_emojis() {
        assert_eq!(ConnectionQuality::Excellent.emoji(), "\u{1f7e2}");
        assert_eq!(ConnectionQuality::Good.emoji(), "\u{1f7e2}");
        assert_eq!(ConnectionQuality::Fair.emoji(), "\u{1f7e1}");
        assert_eq!(ConnectionQuality::Poor.emoji(), "\u{1f7e0}");
        assert_eq!(ConnectionQuality::Bad.emoji(), "\u{1f534}");
    }

    // ── Default impls ──

    #[test]
    fn test_stability_test_state_default() {
        let state = StabilityTestState::default();
        assert!(!state.running);
        assert_eq!(state.progress, 0.0);
        assert!(state.ping_samples.is_empty());
        assert!(state.results.is_none());
    }

    #[test]
    fn test_speed_test_state_default() {
        let state = SpeedTestState::default();
        assert!(!state.running);
        assert_eq!(state.phase, SpeedTestPhase::Idle);
        assert_eq!(state.download_speed, 0.0);
        assert_eq!(state.upload_speed, 0.0);
        assert_eq!(state.phase_progress, 0.0);
        assert!(state.results.is_none());
    }

    #[test]
    fn test_speed_test_phase_labels() {
        assert_eq!(SpeedTestPhase::Idle.label(), "Ready");
        assert_eq!(SpeedTestPhase::Download.label(), "Testing Download");
        assert_eq!(SpeedTestPhase::Upload.label(), "Testing Upload");
        assert_eq!(SpeedTestPhase::Complete.label(), "Complete");
    }

    #[test]
    fn test_network_analyzer_state_default() {
        let state = NetworkAnalyzerState::default();
        assert!(!state.stability.running);
        assert!(!state.speed.running);
    }
}
