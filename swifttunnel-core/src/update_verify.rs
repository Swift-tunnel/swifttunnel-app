//! Verifying that an update really came from us.
//!
//! Both clients update themselves, and neither may install anything it has not
//! checked. The chain is the same for both: a small manifest is signed with our
//! Ed25519 key at release time, and every payload the manifest names carries a
//! SHA-256 that the manifest vouches for. Verify the signature, then verify the
//! payload against the hash inside it, and a tampered download cannot reach
//! `msiexec`.
//!
//! This lives in core because there are two clients. It used to live in the
//! desktop crate alone, which is why Lite had no updater at all: giving it one
//! meant either reaching into the desktop crate or writing a second copy of the
//! signature checking, and a second copy of security code is how the two drift
//! until only one of them is right.

use base64::Engine;
use ring::signature::{ED25519, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// Check an Ed25519 signature over the exact manifest bytes.
///
/// The bytes must be the ones fetched, not a re-serialisation of a parsed
/// manifest: re-encoding changes whitespace and key order and the signature
/// then fails for a manifest that was perfectly good.
pub fn verify_manifest_signature_with_public_key(
    manifest_bytes: &[u8],
    signature_b64: &str,
    public_key_bytes: &[u8],
) -> Result<(), String> {
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| format!("Invalid updater manifest signature encoding: {}", e))?;

    UnparsedPublicKey::new(&ED25519, &public_key_bytes)
        .verify(manifest_bytes, &signature_bytes)
        .map_err(|e| format!("Updater manifest signature verification failed: {}", e))
}

/// Reduce a hash to bare lowercase hex so two spellings of it compare equal.
///
/// The `sha256:` prefix is not decoration. Tauri's `latest.json` writes hashes
/// that way, so dropping the prefix step would fail every desktop update while
/// looking like a signature problem.
pub fn normalize_sha256(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("sha256:") {
        &trimmed[7..]
    } else {
        trimmed
    };
    without_prefix.to_ascii_lowercase()
}

/// Check a payload against the SHA-256 the signed manifest gave for it.
///
/// `label` only names the thing in the error, so a failure says which download
/// was wrong rather than just that one was.
pub fn verify_bytes_sha256(bytes: &[u8], expected_sha256: &str, label: &str) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = format!("{:x}", hasher.finalize());
    let expected = normalize_sha256(expected_sha256);

    if actual != expected {
        return Err(format!(
            "{} SHA256 mismatch: expected '{}', got '{}'",
            label, expected, actual
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn sign_payload(payload: &[u8]) -> (Vec<u8>, String) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let signature = key_pair.sign(payload);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
        (key_pair.public_key().as_ref().to_vec(), signature_b64)
    }

    #[test]
    fn accepts_a_signature_we_made() {
        let manifest = br#"{"version":"1.2.3"}"#;
        let (public_key, signature) = sign_payload(manifest);
        assert!(
            verify_manifest_signature_with_public_key(manifest, &signature, &public_key).is_ok()
        );
    }

    /// Changing the manifest after signing must fail. This is the attack the
    /// signature exists for: a manifest that names a different download.
    #[test]
    fn rejects_a_manifest_edited_after_signing() {
        let manifest = br#"{"version":"1.2.3"}"#;
        let tampered = br#"{"version":"9.9.9"}"#;
        let (public_key, signature) = sign_payload(manifest);
        assert!(
            verify_manifest_signature_with_public_key(tampered, &signature, &public_key).is_err()
        );
    }

    #[test]
    fn rejects_a_doctored_signature() {
        let manifest = br#"{"version":"1.2.3"}"#;
        let (public_key, signature) = sign_payload(manifest);

        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .unwrap();
        bytes[0] ^= 0xAA;
        let doctored = base64::engine::general_purpose::STANDARD.encode(bytes);

        assert!(
            verify_manifest_signature_with_public_key(manifest, &doctored, &public_key).is_err()
        );
    }

    /// A signature from a different key must not pass. Without this, anyone
    /// able to serve a manifest could sign their own.
    #[test]
    fn rejects_a_signature_from_another_key() {
        let manifest = br#"{"version":"1.2.3"}"#;
        let (_theirs, signature) = sign_payload(manifest);
        let (ours, _) = sign_payload(manifest);
        assert!(verify_manifest_signature_with_public_key(manifest, &signature, &ours).is_err());
    }

    #[test]
    fn rejects_signature_that_is_not_base64() {
        let manifest = br#"{"version":"1.2.3"}"#;
        let (public_key, _) = sign_payload(manifest);
        assert!(
            verify_manifest_signature_with_public_key(manifest, "not base64!!", &public_key)
                .is_err()
        );
    }

    /// Tauri writes latest.json hashes as "sha256:abc...". Dropping that
    /// prefix step fails every desktop update, and it fails looking like a
    /// signature problem rather than a formatting one.
    #[test]
    fn the_sha256_prefix_is_stripped() {
        assert_eq!(normalize_sha256("SHA256:ABCDEF1234"), "abcdef1234");
        assert_eq!(normalize_sha256("sha256:abcdef1234"), "abcdef1234");
        assert_eq!(normalize_sha256("  abcdef1234  "), "abcdef1234");
        // Not a prefix, so nothing is removed.
        assert_eq!(normalize_sha256("abcdef"), "abcdef");
    }

    /// A payload verifies against either spelling of the same hash.
    #[test]
    fn a_prefixed_hash_still_matches_its_payload() {
        let bytes = b"swifttunnel";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = format!("{:x}", hasher.finalize());
        assert!(verify_bytes_sha256(bytes, &format!("SHA256:{hash}"), "latest.json").is_ok());
    }

    #[test]
    fn a_payload_matching_its_hash_passes() {
        // sha256 of "swifttunnel"
        let bytes = b"swifttunnel";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = format!("{:x}", hasher.finalize());
        assert!(verify_bytes_sha256(bytes, &hash, "installer").is_ok());
        // Formatting must not matter.
        assert!(verify_bytes_sha256(bytes, &format!("  {}  ", hash.to_uppercase()), "x").is_ok());
    }

    /// A single changed byte has to fail, or the hash is decorative.
    #[test]
    fn a_payload_that_does_not_match_its_hash_fails() {
        let mut hasher = Sha256::new();
        hasher.update(b"swifttunnel");
        let hash = format!("{:x}", hasher.finalize());

        let error = verify_bytes_sha256(b"swifttunnel!", &hash, "installer")
            .expect_err("a changed payload must not verify");
        assert!(
            error.contains("installer"),
            "the error should name what failed, got: {error}"
        );
    }

    #[test]
    fn an_empty_payload_does_not_pass_a_real_hash() {
        let mut hasher = Sha256::new();
        hasher.update(b"swifttunnel");
        let hash = format!("{:x}", hasher.finalize());
        assert!(verify_bytes_sha256(b"", &hash, "installer").is_err());
    }
}
