//! Custom profile for an application-defined ASCII handle, with explicit ownership.

// ANCHOR: custom-profile
use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexMetadata, BlindIndexSpec, Codec, CodecError,
    CodecErrorKind, Encrypted, EncryptionKey, EncryptionKeyProvider, KeyId, KeyProviderError,
    LocalBlindIndexKeyring, LocalEncryptionKeyring, Secret,
};
use zeroize::Zeroizing;

struct HandleCodec;

// Application policy: 1–64 ASCII letters, digits or hyphens; preserve case in storage.
fn valid_handle(bytes: &[u8]) -> bool {
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

impl Codec<Secret<String>> for HandleCodec {
    fn encode(value: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let bytes = value.expose_secret().as_bytes();
        if !valid_handle(bytes) {
            return Err(CodecError::new(CodecErrorKind::Encoding));
        }
        // Allocate once before copying sensitive bytes; no plaintext-bearing growth.
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<Secret<String>, CodecError> {
        if !valid_handle(bytes) {
            return Err(CodecError::new(CodecErrorKind::Decoding));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))?;
        Ok(Secret::new(text.to_owned()))
    }
}

cryptbox::profile! {
    Handle: Secret<String> {
        id: "dcaa3c69-1767-49a1-8476-36555eaf54bf",
        name: "account-handle",
        codec: HandleCodec,
        binding: field_bound,
    }
}

struct HandleEquality;

impl BlindIndexMetadata for HandleEquality {
    const ID: cryptbox::IndexId = cryptbox::index_id!("6c0e20d5-cb30-4b84-8dd1-995f872b417c");
    const BITS: usize = 128;
}

impl BlindIndexSpec<Secret<String>> for HandleEquality {
    fn normalize(input: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        let bytes = input.expose_secret().as_bytes();
        if !valid_handle(bytes) {
            return Err(BlindIndexError::new());
        }
        let mut normalized = Zeroizing::new(bytes.to_vec());
        normalized.make_ascii_lowercase();
        Ok(normalized)
    }
}

// An application-owned snapshot. None means loading/refresh failed, not "unknown ID".
struct CachedEncryptionKeys {
    snapshot: Option<LocalEncryptionKeyring>,
}

impl EncryptionKeyProvider for CachedEncryptionKeys {
    fn current_key(&self) -> Result<EncryptionKey, KeyProviderError> {
        self.snapshot
            .as_ref()
            .ok_or(KeyProviderError::Unavailable)?
            .current_key()
    }

    fn key(&self, id: KeyId) -> Result<Option<EncryptionKey>, KeyProviderError> {
        self.snapshot
            .as_ref()
            .ok_or(KeyProviderError::Unavailable)?
            .key(id)
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demonstration only. Load stable key/ID pairs for durable data.
    let keys = CachedEncryptionKeys {
        snapshot: Some(LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?),
    };
    let old_index_key = BlindIndexKey::generate()?; // Independent of encryption keys.
    let index_writer = LocalBlindIndexKeyring::new(old_index_key.clone(), [])?;
    let value = Encrypted::<_, Handle>::new(Secret::new("Alice-7".to_owned()));
    let prepared = value
        .prepare_with(&(), &keys)?
        .with_index_with::<HandleEquality>(&index_writer)?;
    let ciphertext = prepared.ciphertext().clone();
    let stored_index = prepared.index::<HandleEquality>()?.as_bytes().to_vec();
    // These two representations belong in one atomic storage write.
    drop(prepared); // Releases the borrow, not the source plaintext.

    // After index-key promotion, query every readable generation, including old data.
    let index_reader = LocalBlindIndexKeyring::new(BlindIndexKey::generate()?, [old_index_key])?;
    let query = Secret::new("ALICE-7".to_owned());
    let probes = cryptbox::blind_index_probes::<HandleEquality, _, cryptbox::FieldBound<Handle>>(
        &query,
        &(),
        &index_reader,
    )?;
    assert_eq!(probes.len(), 2);
    assert!(probes.iter().any(|probe| probe.as_bytes() == stored_index));
    // An index hit is only a candidate: authenticate and compare normalized plaintext.
    let decrypted = ciphertext.decrypt_with(&(), &keys)?.into_secret();
    assert!(cryptbox::verify_blind_index_candidate::<HandleEquality, _>(
        &query, &decrypted
    )?);
    assert_eq!(decrypted.expose_secret(), "Alice-7");
    assert_eq!(value.expose_secret().expose_secret(), "Alice-7");
    println!("Custom profile round trip and normalized lookup succeeded.");
    Ok(())
}
// ANCHOR_END: custom-profile

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_secret_codec_round_trips_without_consuming_the_source() -> Result<(), cryptbox::Error>
    {
        main()
    }

    #[test]
    fn lookup_uses_case_insensitive_equality_and_rejects_other_handles()
    -> Result<(), cryptbox::Error> {
        let alice = Secret::new("Alice-7".to_owned());
        let query = Secret::new("ALICE-7".to_owned());
        let bob = Secret::new("Bob-7".to_owned());
        assert_eq!(&*HandleEquality::normalize(&alice)?, b"alice-7");
        assert!(cryptbox::verify_blind_index_candidate::<HandleEquality, _>(
            &alice, &query
        )?);
        assert!(!cryptbox::verify_blind_index_candidate::<HandleEquality, _>(&bob, &query)?);
        Ok(())
    }

    #[test]
    fn provider_retains_history_and_distinguishes_unknown_from_unavailable()
    -> Result<(), cryptbox::Error> {
        let old = EncryptionKey::generate()?;
        let current = EncryptionKey::generate()?;
        let unknown = EncryptionKey::generate()?.id();
        let writer = LocalEncryptionKeyring::new(old.clone(), [])?;
        let value = Encrypted::<_, Handle>::new(Secret::new("Alice-7".to_owned()));
        let ciphertext = value.encrypt_with(&(), &writer)?;
        let reader = CachedEncryptionKeys {
            snapshot: Some(LocalEncryptionKeyring::new(current.clone(), [old.clone()])?),
        };
        assert_eq!(reader.current_key()?.id(), current.id());
        assert_eq!(reader.key(old.id())?.unwrap().id(), old.id());
        assert_eq!(reader.key(current.id())?.unwrap().id(), current.id());
        assert!(reader.key(unknown)?.is_none());
        assert_eq!(
            ciphertext
                .decrypt_with(&(), &reader)?
                .into_secret()
                .expose_secret(),
            "Alice-7"
        );
        let retired = CachedEncryptionKeys {
            snapshot: Some(LocalEncryptionKeyring::new(current, [])?),
        };
        assert_eq!(
            ciphertext.decrypt_with(&(), &retired).unwrap_err(),
            cryptbox::Error::UnknownEncryptionKey(old.id())
        );
        let unavailable = CachedEncryptionKeys { snapshot: None };
        assert_eq!(
            unavailable.current_key().unwrap_err(),
            KeyProviderError::Unavailable
        );
        assert_eq!(
            unavailable.key(old.id()).unwrap_err(),
            KeyProviderError::Unavailable
        );
        assert_eq!(
            ciphertext.decrypt_with(&(), &unavailable).unwrap_err(),
            cryptbox::Error::KeyProviderUnavailable
        );
        Ok(())
    }

    #[test]
    fn invalid_sensitive_inputs_return_only_sanitized_categories() -> Result<(), cryptbox::Error> {
        let invalid = Secret::new("private handle!".to_owned());
        let encode = HandleCodec::encode(&invalid).unwrap_err();
        assert_eq!(encode.kind(), CodecErrorKind::Encoding);
        assert_eq!(encode.to_string(), "codec encoding failed");
        assert_eq!(format!("{encode:?}"), "CodecError { kind: Encoding }");
        let decode = HandleCodec::decode(b"private handle!").unwrap_err();
        assert_eq!(decode.kind(), CodecErrorKind::Decoding);
        assert_eq!(decode.to_string(), "codec decoding failed");
        assert_eq!(format!("{decode:?}"), "CodecError { kind: Decoding }");
        let normalize = HandleEquality::normalize(&invalid).unwrap_err();
        assert_eq!(normalize.to_string(), "blind-index normalization failed");
        assert_eq!(format!("{normalize:?}"), "BlindIndexError");

        // Encoding failure is sanitized at the storage boundary too.
        let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let value = Encrypted::<_, Handle>::new(invalid);
        assert_eq!(
            value.encrypt_with(&(), &keys).unwrap_err(),
            cryptbox::Error::CodecFailed(encode)
        );
        Ok(())
    }

    #[test]
    fn a_decrypted_string_can_be_moved_into_secret() -> Result<(), cryptbox::Error> {
        cryptbox::profile! {
            PlainHandle: String {
                id: "dcaa3c69-1767-49a1-8476-36555eaf54bf",
                name: "account-handle",
                codec: cryptbox::Utf8,
                binding: field_bound,
            }
        }
        let keys = LocalEncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let value = Encrypted::<_, PlainHandle>::new("Alice-7".to_owned());
        let ciphertext = value.encrypt_with(&(), &keys)?;
        let decrypted = ciphertext.decrypt_with(&(), &keys)?;
        let secret = Secret::new(decrypted.into_secret());
        assert_eq!(secret.expose_secret(), "Alice-7");
        Ok(())
    }
}
