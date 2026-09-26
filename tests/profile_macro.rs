//! Public-boundary tests for declarative encryption profiles.

use cryptbox::{
    BlindIndexKeyProvider, Ciphertext, Encrypted, EncryptionKey, EncryptionKeyProvider,
    EncryptionProfile, Field, GlobalKeyContext, KeyContext, KeyProviderError,
    LocalEncryptionKeyring, NoPadding, PadToBlock, Raw, Utf8,
};

cryptbox::profile! {
    /// Email encrypted with field binding.
    pub UserEmail: String {
        id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
        name: "user-email",
        codec: Utf8,
    }
}

cryptbox::profile! {
    /// Email encrypted with field binding and block padding.
    pub PaddedEmail: String {
        id: "b49a65a7-93e6-4b09-8f04-a502578045c1",
        name: "padded-email",
        codec: Utf8,
        padding: PadToBlock<16>,
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
    /// API token encrypted with an application key context.
    pub ApiToken: Vec<u8> {
        id: "de8c983c-7d2b-4c4f-8162-f7193010de55",
        name: "api-token",
        codec: Raw,
        keys: ApplicationKeys,
    }
}

#[test]
fn profile_declares_field_metadata_and_policy() {
    fn assert_policy<P>()
    where
        P: EncryptionProfile<
                Value = String,
                Codec = Utf8,
                Keys = GlobalKeyContext,
                Padding = NoPadding,
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
fn profile_accepts_custom_keys() {
    fn assert_policy<P>()
    where
        P: EncryptionProfile<
                Value = Vec<u8>,
                Codec = Raw,
                Keys = ApplicationKeys,
                Padding = NoPadding,
            >,
    {
    }

    assert_policy::<ApiToken>();
    assert_eq!(
        ApiToken::ID.to_string(),
        "de8c983c-7d2b-4c4f-8162-f7193010de55"
    );
    assert_eq!(ApiToken::NAME, "api-token");
}

#[test]
fn profile_accepts_an_explicit_padding_policy() {
    fn assert_policy<P>()
    where
        P: EncryptionProfile<
                Value = String,
                Codec = Utf8,
                Keys = GlobalKeyContext,
                Padding = PadToBlock<16>,
            >,
    {
    }

    assert_policy::<PaddedEmail>();
}

cryptbox::profile! {
    /// Email declared with only its field ID.
    pub DefaultedEmail: String { id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25" }
}

cryptbox::profile! {
    /// Token declared with only its field ID.
    pub DefaultedToken: Vec<u8> { id: "de8c983c-7d2b-4c4f-8162-f7193010de55" }
}

cryptbox::profile! {
    /// Optional keys may appear in any order.
    pub ReorderedEmail: String {
        padding: PadToBlock<16>,
        keys: ApplicationKeys,
        id: "b49a65a7-93e6-4b09-8f04-a502578045c1",
    }
}

// These defaults are persistent schema: changing them would silently misread stored data.
#[test]
fn omitted_keys_select_permanent_defaults() {
    fn assert_policy<P, V, C>()
    where
        P: EncryptionProfile<Value = V, Codec = C, Keys = GlobalKeyContext, Padding = NoPadding>,
    {
    }

    assert_policy::<DefaultedEmail, String, Utf8>();
    assert_policy::<DefaultedToken, Vec<u8>, Raw>();
    assert_eq!(DefaultedEmail::NAME, "DefaultedEmail");
    assert_eq!(DefaultedToken::NAME, "DefaultedToken");
    assert_eq!(DefaultedEmail::ID, UserEmail::ID);
}

#[test]
fn optional_keys_are_accepted_in_any_order() {
    fn assert_policy<P>()
    where
        P: EncryptionProfile<
                Value = String,
                Codec = Utf8,
                Keys = ApplicationKeys,
                Padding = PadToBlock<16>,
            >,
    {
    }

    assert_policy::<ReorderedEmail>();
    assert_eq!(ReorderedEmail::ID, PaddedEmail::ID);
}

#[test]
fn defaulted_profile_reads_ciphertext_from_the_explicit_declaration() {
    let keys = LocalEncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();
    let ciphertext = Encrypted::<UserEmail>::new("mark@example.com")
        .encrypt_with(&keys)
        .unwrap();
    let read = Ciphertext::<DefaultedEmail>::from_bytes(ciphertext.into_bytes()).unwrap();

    assert_eq!(
        read.decrypt_with(&keys).unwrap().expose_secret(),
        "mark@example.com"
    );
}
