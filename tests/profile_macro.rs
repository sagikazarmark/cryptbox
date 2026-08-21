//! Public-boundary tests for declarative encryption profiles.

use cryptbox::{
    BlindIndexKeyProvider, EncryptionKeyProvider, EncryptionProfile, Field, FieldBound,
    GlobalKeyContext, KeyContext, KeyProviderError, Raw, Unbound, Utf8,
};

cryptbox::profile! {
    /// Email encrypted with field binding.
    pub UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: Utf8,
        binding: field_bound,
    }
}

/// Application-specific key context used to exercise macro customization.
pub struct ApplicationKeys;

impl KeyContext for ApplicationKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        Err(KeyProviderError::NotInitialized)
    }

    fn blind_index_keys() -> Result<&'static dyn BlindIndexKeyProvider, KeyProviderError> {
        Err(KeyProviderError::NotInitialized)
    }
}

cryptbox::profile! {
    /// API token encrypted without field binding.
    pub ApiToken: Vec<u8> {
        id: "de8c983c-7d2b-4c4f-8162-f7193010de55",
        name: "api-token",
        codec: Raw,
        binding: unbound,
        keys: ApplicationKeys,
    }
}

#[test]
fn field_bound_profile_declares_field_metadata_and_policy() {
    fn assert_policy<P>()
    where
        P: Field
            + EncryptionProfile<
                String,
                Codec = Utf8,
                Binding = FieldBound<P>,
                Keys = GlobalKeyContext,
            >,
    {
    }

    assert_policy::<UserEmail>();
    assert_eq!(
        UserEmail::ID.to_string(),
        "ca274e85-63c4-4f7d-a255-2dfecbfe5e25"
    );
    assert_eq!(UserEmail::NAME, "user-email");
}

#[test]
fn unbound_profile_requires_explicit_binding_and_accepts_custom_keys() {
    fn assert_policy<P>()
    where
        P: Field
            + EncryptionProfile<Vec<u8>, Codec = Raw, Binding = Unbound, Keys = ApplicationKeys>,
    {
    }

    assert_policy::<ApiToken>();
    assert_eq!(
        ApiToken::ID.to_string(),
        "de8c983c-7d2b-4c4f-8162-f7193010de55"
    );
    assert_eq!(ApiToken::NAME, "api-token");
}
