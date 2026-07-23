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
    let target = target_lang.trim().to_lowercase();
    if text.trim().is_empty() || target.is_empty() || target == "en" {
        return Ok(text);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("translate client: {e}"))?;

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

    let payload: Value = response
        .json()
        .await
        .map_err(|e| format!("translate parse: {e}"))?;

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
