use reqwest::header::USER_AGENT;
use serde_json::Value;
use std::time::Duration;

const TRANSLATE_ENDPOINT: &str = "https://translate.googleapis.com/translate_a/single";
const TRANSLATE_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/122.0 Safari/537.36";

/// Machine-translate a blob of UI text into `target_lang`.
///
/// The frontend batches many short UI strings joined by newlines and splits the
/// result back apart, so we concatenate every returned segment verbatim to keep
/// the line structure intact. Uses Google's public `gtx` endpoint — no API key
/// required. Runs in Rust (via reqwest) so it is not subject to the webview CSP,
/// which only allows swifttunnel.net / supabase.co.
#[tauri::command]
pub async fn i18n_translate(text: String, target_lang: String) -> Result<String, String> {
    if text.len() > 32 * 1024 || target_lang.len() > 16 {
        return Err("Translation request is too large.".into());
    }
    let target = target_lang.trim().to_lowercase();
    if !target.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
        return Err("Invalid translation language.".into());
    }
    if text.trim().is_empty() || target.is_empty() || target == "en" {
        return Ok(text);
    }

    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| format!("translate client: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)?;

    let response = client
        .get(TRANSLATE_ENDPOINT)
        .query(&[
            ("client", "gtx"),
            ("sl", "auto"),
            ("tl", target.as_str()),
            ("dt", "t"),
            ("q", text.as_str()),
        ])
        .header(USER_AGENT, TRANSLATE_USER_AGENT)
        .send()
        .await
        .map_err(|e| format!("translate request: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("translate status {}", response.status()));
    }

    let body =
        swifttunnel_core::http_body::read_bounded(response, 256 * 1024, "translation").await?;
    let payload: Value =
        serde_json::from_slice(&body).map_err(|e| format!("translate parse: {e}"))?;

    // gtx shape: [[["translated","original",...], ["seg2","orig2",...]], ...]
    // Concatenate every segment's translated text to rebuild the full blob;
    // Google keeps the source newlines inside the segment text.
    let segments = payload
        .get(0)
        .and_then(Value::as_array)
        .ok_or_else(|| "translate: unexpected response shape".to_string())?;

    let mut out = String::with_capacity(text.len());
    for seg in segments {
        if let Some(part) = seg.get(0).and_then(Value::as_str) {
            out.push_str(part);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oversized_or_invalid_translation_requests_fail_before_network_work() {
        assert!(
            i18n_translate("x".repeat(32 * 1024 + 1), "fr".into())
                .await
                .is_err()
        );
        assert!(
            i18n_translate("Connected".into(), "x".repeat(17))
                .await
                .is_err()
        );
        assert!(
            i18n_translate("Connected".into(), "../fr".into())
                .await
                .is_err()
        );
        assert_eq!(
            i18n_translate("Connected".into(), "en".into())
                .await
                .unwrap(),
            "Connected"
        );
    }
}
