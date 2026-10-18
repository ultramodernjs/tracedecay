use tracedecay_domain::canonical_text::is_tagged_lowercase_hex;

use super::length_prefixed_sha256_hex;
use super::structured_text::sanitize_provider_metadata_text;

const PROTECTION_DOMAIN_V1: &[u8] = b"tracedecay.structural-identity-protection.v1";
const PROTECTION_PREFIX_V1: &str = "privacy.structural-id.v1.";
const CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V1: &str =
    "tracedecay-claude-observation-source-v1-sha256-";
const CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V2: &str =
    "tracedecay-claude-observation-source-v2-sha256-";

#[derive(Clone, Copy, Debug)]
pub struct StructuralIdProtectionError;

/// True when `value` is already a protected structural-ID token or an opaque
/// Claude observation source digest that must not be re-hashed.
pub(crate) fn is_already_protected_structural_id(value: &str) -> bool {
    is_tagged_lowercase_hex(value, PROTECTION_PREFIX_V1, 64)
        || is_tagged_lowercase_hex(value, CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V1, 64)
        || is_tagged_lowercase_hex(value, CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V2, 64)
}

/// True for the message identity TraceDecay's own host plugins mint for a
/// synced turn: `tracedecay_sync_<batch>_<unix nanos>_<index>_<role>`.
///
/// The id is public by construction, but as one token it is long enough and
/// mixed enough for the entropy detector, and whether it crosses that
/// threshold depends on the digits of the timestamp: some turns kept their
/// id and others came back as a protected digest, so one message carried
/// two canonical identities depending on the clock.
pub(crate) fn is_public_sync_message_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("tracedecay_sync_") else {
        return false;
    };
    let mut parts = rest.splitn(4, '_');
    let numeric = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    numeric(parts.next())
        && numeric(parts.next())
        && numeric(parts.next())
        && parts.next().is_some_and(|role| {
            !role.is_empty() && role.bytes().all(|byte| byte.is_ascii_lowercase())
        })
}

/// Replaces credential-shaped structural identifiers with a stable,
/// versioned digest. Public identifiers and values already protected by this
/// version are preserved byte-for-byte.
pub fn protect_sensitive_structural_id(value: &str) -> Result<String, StructuralIdProtectionError> {
    if is_already_protected_structural_id(value) || is_public_sync_message_id(value) {
        return Ok(value.to_owned());
    }
    let sanitized = sanitize_provider_metadata_text(value).ok_or(StructuralIdProtectionError)?;
    if sanitized == value {
        return Ok(value.to_owned());
    }

    Ok(format!(
        "{PROTECTION_PREFIX_V1}{}",
        length_prefixed_sha256_hex(&[PROTECTION_DOMAIN_V1, value.as_bytes()])
    ))
}

/// Protects an optional structural identifier. Empty and missing values stay
/// absent; already-protected and public values are preserved byte-for-byte.
pub fn protect_optional_sensitive_structural_id(
    value: Option<&str>,
) -> Result<Option<String>, StructuralIdProtectionError> {
    match value {
        None | Some("") => Ok(None),
        Some(value) => protect_sensitive_structural_id(value).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V1, CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V2,
        PROTECTION_PREFIX_V1, is_already_protected_structural_id,
        protect_optional_sensitive_structural_id, protect_sensitive_structural_id,
    };

    /// Split so this file never contains a contiguous credential-shaped token.
    /// The tail is base32 (`[A-Z2-7]`) because that is the alphabet real AWS
    /// key ids use, and the vendored rule reads it precisely.
    fn credential_shaped_fixture() -> String {
        ["AKIA", "SYNTHETIC", "CANARY", "7"].concat()
    }

    #[test]
    fn protection_is_stable_idempotent_and_preserves_public_ids() {
        let raw = credential_shaped_fixture();
        let protected = protect_sensitive_structural_id(&raw).unwrap();
        assert!(protected.starts_with(PROTECTION_PREFIX_V1));
        assert_ne!(protected, raw);
        assert_eq!(
            protect_sensitive_structural_id(&protected).unwrap(),
            protected
        );
        assert_eq!(
            protect_sensitive_structural_id("session.public-123").unwrap(),
            "session.public-123"
        );
        assert_eq!(
            protect_optional_sensitive_structural_id(Some(" session.public-123 ")).unwrap(),
            Some(" session.public-123 ".to_string())
        );
        let opaque_source = concat!(
            "tracedecay-claude-observation-source-v1-sha256-",
            "c35dddcc2fa7cfbcc40232d6f298e54f5a471a51227387a4e6a31b8f48e1ecb8"
        );
        assert_eq!(
            protect_sensitive_structural_id(opaque_source).unwrap(),
            opaque_source
        );
        let opaque_path_source = concat!(
            "tracedecay-claude-observation-source-v2-sha256-",
            "5d590176d45bdfe8395fde369964c8fc3c980d91912824a3333f84b13fb50e52"
        );
        assert_eq!(
            protect_sensitive_structural_id(opaque_path_source).unwrap(),
            opaque_path_source
        );
    }

    #[test]
    fn forged_protection_prefixes_do_not_bypass_secret_scanning() {
        let cases = [
            (
                format!("{PROTECTION_PREFIX_V1}sk-test-123456"),
                "privacy.structural-id.v1.ffa1e647b38b0edac27c24ddaac8940f10c9399949745412b6b4576ffa76c6e8",
            ),
            (
                format!("{CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V1}sk-test-123456"),
                "privacy.structural-id.v1.d7c35a12a51a3d498dd78997877d8904b1f203f5a1706f8359b86ba4ac162896",
            ),
            (
                format!("{CLAUDE_OBSERVATION_SOURCE_ID_PREFIX_V2}sk-test-123456"),
                "privacy.structural-id.v1.48bcb6a0df7b81d290220994e1c46c0c2058ea69d45776ee6ebfad132579062c",
            ),
        ];
        for (forged, expected) in cases {
            assert!(!is_already_protected_structural_id(&forged));
            let protected = protect_sensitive_structural_id(&forged).unwrap();
            assert_eq!(protected, expected);
            assert!(is_already_protected_structural_id(&protected));
            assert!(!protected.contains("sk-test-123456"));
        }
    }
    #[test]
    fn plugin_sync_message_ids_stay_public_whatever_their_timestamp() {
        // Both score just above the entropy threshold as one token; a
        // timestamp a few digits apart scores below it.
        for id in [
            "tracedecay_sync_1_1792008757259472364_0_user",
            "tracedecay_sync_1_1792008757259472364_1_assistant",
            "tracedecay_sync_1_1760000000000000000_0_user",
        ] {
            assert_eq!(protect_sensitive_structural_id(id).unwrap(), id);
        }
        assert_ne!(
            protect_sensitive_structural_id("tracedecay_sync_x_AKIAIOSFODNN7EXAMPLE_0_user")
                .unwrap(),
            "tracedecay_sync_x_AKIAIOSFODNN7EXAMPLE_0_user"
        );
    }
}
