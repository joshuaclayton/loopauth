use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

#[expect(
    clippy::struct_field_names,
    reason = "field names intentionally mirror the PKCE spec terminology"
)]
pub struct PkceChallenge {
    pub(crate) code_verifier: String,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: &'static str,
}

impl PkceChallenge {
    #[must_use]
    pub(crate) fn generate() -> Self {
        // 48 random bytes → 64 base64url chars (within RFC 7636 bounds of 43–128)
        // Use uuid v4 bytes to avoid getrandom 0.2/0.3 version ambiguity.
        // uuid v4 uses OS RNG via getrandom internally - cryptographically random.
        use uuid::Uuid;
        let b1 = Uuid::new_v4().into_bytes();
        let b2 = Uuid::new_v4().into_bytes();
        let b3 = Uuid::new_v4().into_bytes();
        let mut bytes = [0_u8; 48];
        bytes[..16].copy_from_slice(&b1);
        bytes[16..32].copy_from_slice(&b2);
        bytes[32..48].copy_from_slice(&b3);
        let code_verifier = URL_SAFE_NO_PAD.encode(bytes);

        let hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(hash);

        Self {
            code_verifier,
            code_challenge,
            code_challenge_method: "S256",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PkceChallenge;

    #[test]
    fn verifier_contains_only_url_safe_chars() {
        let pkce = PkceChallenge::generate();
        assert!(
            pkce.code_verifier
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "code_verifier contains non-URL-safe characters: {}",
            pkce.code_verifier
        );
    }

    #[test]
    fn verifier_does_not_contain_plus() {
        let pkce = PkceChallenge::generate();
        assert!(
            !pkce.code_verifier.contains('+'),
            "code_verifier must not contain +"
        );
    }

    #[test]
    fn verifier_does_not_contain_slash() {
        let pkce = PkceChallenge::generate();
        assert!(
            !pkce.code_verifier.contains('/'),
            "code_verifier must not contain /"
        );
    }

    #[test]
    fn verifier_does_not_contain_equals() {
        let pkce = PkceChallenge::generate();
        assert!(
            !pkce.code_verifier.contains('='),
            "code_verifier must not contain ="
        );
    }

    #[test]
    fn verifier_length_within_rfc_bounds() {
        for _ in 0..100 {
            let pkce = PkceChallenge::generate();
            assert!(
                pkce.code_verifier.len() >= 43,
                "code_verifier too short: {}",
                pkce.code_verifier.len()
            );
            assert!(
                pkce.code_verifier.len() <= 128,
                "code_verifier too long: {}",
                pkce.code_verifier.len()
            );
        }
    }

    #[test]
    fn challenge_contains_only_url_safe_chars() {
        let pkce = PkceChallenge::generate();
        assert!(
            !pkce.code_challenge.contains('+'),
            "code_challenge must not contain +"
        );
        assert!(
            !pkce.code_challenge.contains('/'),
            "code_challenge must not contain /"
        );
        assert!(
            !pkce.code_challenge.contains('='),
            "code_challenge must not contain ="
        );
    }

    #[test]
    fn challenge_method_is_s256() {
        let pkce = PkceChallenge::generate();
        assert_eq!(pkce.code_challenge_method, "S256");
    }

    #[test]
    fn challenge_matches_expected_computation() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest, Sha256};
        let pkce = PkceChallenge::generate();
        let hash = Sha256::digest(pkce.code_verifier.as_bytes());
        let expected_challenge = URL_SAFE_NO_PAD.encode(hash);
        assert_eq!(
            pkce.code_challenge, expected_challenge,
            "challenge does not match BASE64URL(SHA256(verifier))"
        );
    }
}
