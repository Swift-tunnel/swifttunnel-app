//! Read-only account access. The relay ticket remains the authorization gate.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LicenseStatus {
    NotLaunched {
        enforced: bool,
    },
    Ready {
        enforced: bool,
        tier: LicenseTier,
        unlimited: bool,
        available_seconds: Option<u64>,
        reserved_seconds: Option<u64>,
        expires_at: Option<String>,
        resets_at: Option<String>,
        checked_at: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    Free,
    Plus,
    Pro,
}

impl LicenseStatus {
    pub fn summary(&self) -> String {
        match self {
            Self::NotLaunched { .. } => "Licenses are not available yet".into(),
            Self::Ready {
                tier,
                unlimited,
                available_seconds,
                ..
            } => {
                let plan = match tier {
                    LicenseTier::Free => "Free",
                    LicenseTier::Plus => "Plus",
                    LicenseTier::Pro => "Pro",
                };
                if *unlimited {
                    format!("{plan}: unlimited play during your pass")
                } else {
                    format!(
                        "{plan}: {} min available for new leases",
                        available_seconds.unwrap_or(0) / 60
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_and_unknown_plans_are_not_zero_balances() {
        assert!(serde_json::from_str::<LicenseStatus>(r#"{"state":"unavailable"}"#).is_err());
        assert!(serde_json::from_str::<LicenseStatus>(r#"{"state":"ready","enforced":true,"tier":"unknown","unlimited":false,"checked_at":"now"}"#).is_err());
    }
    #[test]
    fn unlimited_is_distinct_from_zero_available() {
        let status: LicenseStatus = serde_json::from_str(r#"{"state":"ready","enforced":true,"tier":"pro","unlimited":true,"available_seconds":null,"reserved_seconds":null,"expires_at":null,"resets_at":null,"checked_at":"now"}"#).unwrap();
        assert!(status.summary().contains("unlimited"));
    }
}
