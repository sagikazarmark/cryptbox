//! Custom field for an application-defined ASCII handle, with explicit ownership.

// ANCHOR: custom-field
use std::sync::{PoisonError, RwLock};

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, Codec, CodecError,
    CodecErrorKind, EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, Field, FieldId,
    FieldOnly, KeyScope, Padding, Sealed, Secret,
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
    const ID: &'static str = "handle/1";

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

// The field names the validating codec explicitly. `<Secret<String> as Plaintext>::Codec`
// (plain UTF-8) would store the same bytes but skip the handle policy.
struct Handle;

impl Field for Handle {
    const ID: FieldId = cryptbox::field_id!("dcaa3c69-1767-49a1-8476-36555eaf54bf");
    const PADDING: Padding = Padding::NONE;
    const RECORD: bool = false;
    type Value = Secret<String>;
    type Codec = HandleCodec;
    type Binding = FieldOnly;
    type Indexes = (HandleEquality,);
}

struct HandleEquality;

impl BlindIndexSpec for HandleEquality {
    type Field = Handle;
    const ID: cryptbox::IndexId = cryptbox::index_id!("6c0e20d5-cb30-4b84-8dd1-995f872b417c");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "handle-lowercase/1";
    type Query = Secret<String>;

    fn normalize_query(input: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        let bytes = input.expose_secret().as_bytes();
        if !valid_handle(bytes) {
            return Err(BlindIndexError::new());
        }
        let mut normalized = Zeroizing::new(bytes.to_vec());
        normalized.make_ascii_lowercase();
        Ok(normalized)
    }

    fn normalize_value(value: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

// An application-owned snapshot that a background task refreshes from the KMS.
// None means loading/refresh failed, not "unknown ID".
struct CachedEncryptionKeys {
    snapshot: RwLock<Option<EncryptionKeyring>>,
}

impl CachedEncryptionKeys {
    fn new(snapshot: Option<EncryptionKeyring>) -> Self {
        Self {
            snapshot: RwLock::new(snapshot),
        }
    }

    // Operations already in flight keep the keyring they were handed.
    fn refresh(&self, keyring: EncryptionKeyring) {
        *self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(keyring);
    }
}

impl EncryptionKeySource for CachedEncryptionKeys {
    fn encryption_keyring(&self, _: FieldId, _: &KeyScope) -> Result<EncryptionKeyring, Error> {
        // Cloning shares the keys; it does not copy key material.
        self.snapshot
            .read()
            .map_err(|_| Error::KeysUnavailable)?
            .clone()
            .ok_or(Error::KeysUnavailable)
    }
}

fn main() -> Result<(), cryptbox::Error> {
    // Ephemeral demonstration only. Load stable key/ID pairs for durable data.
    let old_key = EncryptionKey::generate()?;
    let keys = CachedEncryptionKeys::new(Some(EncryptionKeyring::new(old_key.clone(), [])?));
    let old_index_key = BlindIndexKey::generate()?; // Independent of encryption keys.
    let index_writer = BlindIndexKeyring::new(old_index_key.clone(), [])?;
    let value = Secret::new("Alice-7".to_owned());
    let prepared = Sealed::<Handle>::prepare(&value, (), &keys)?
        .with_index_with::<HandleEquality>(&index_writer)?;
    let sealed = prepared.sealed().clone();
    let stored_index = prepared.index::<HandleEquality>()?.as_bytes().to_vec();
    // These two representations belong in one atomic storage write.
    drop(prepared); // Releases the borrow, not the source plaintext.

    // A KMS refresh promotes a new encryption key and keeps the old one readable.
    keys.refresh(EncryptionKeyring::new(
        EncryptionKey::generate()?,
        [old_key],
    )?);

    // After index-key promotion, query every readable generation, including old data.
    let index_reader = BlindIndexKeyring::new(BlindIndexKey::generate()?, [old_index_key])?;
    let query = Secret::new("ALICE-7".to_owned());
    let probes = HandleEquality::probes_with(&query, &(), &index_reader)?;
    assert_eq!(probes.len(), 2);
    assert!(probes.iter().any(|probe| probe.as_bytes() == stored_index));
    // An index hit is only a candidate: authenticate and compare normalized plaintext.
    let opened = sealed.open((), &keys)?;
    assert!(HandleEquality::verify_candidate(&query, &opened)?);
    assert_eq!(opened.expose_secret(), "Alice-7");
    assert_eq!(value.expose_secret(), "Alice-7");
    println!("Custom field round trip and normalized lookup succeeded.");
    Ok(())
}
// ANCHOR_END: custom-field

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
        assert_eq!(&*HandleEquality::normalize_value(&alice)?, b"alice-7");
        assert!(HandleEquality::verify_candidate(&alice, &query)?);
        assert!(!HandleEquality::verify_candidate(&bob, &query)?);
        Ok(())
    }

    #[test]
    fn source_retains_history_and_distinguishes_unknown_from_unavailable()
    -> Result<(), cryptbox::Error> {
        let old = EncryptionKey::generate()?;
        let current = EncryptionKey::generate()?;
        let unknown = EncryptionKey::generate()?.id();
        let writer = EncryptionKeyring::new(old.clone(), [])?;
        let value = Secret::new("Alice-7".to_owned());
        let sealed = Sealed::<Handle>::seal(&value, (), &writer)?;
        let reader = CachedEncryptionKeys::new(Some(EncryptionKeyring::new(
            current.clone(),
            [old.clone()],
        )?));
        let snapshot = reader.encryption_keyring(Handle::ID, &KeyScope::of(&FieldOnly)?)?;
        assert_eq!(snapshot.current().id(), current.id());
        assert_eq!(snapshot.get(old.id()).unwrap().id(), old.id());
        assert_eq!(snapshot.get(current.id()).unwrap().id(), current.id());
        assert!(snapshot.get(unknown).is_none());
        assert_eq!(sealed.open((), &reader)?.expose_secret(), "Alice-7");
        let retired = CachedEncryptionKeys::new(Some(EncryptionKeyring::new(current, [])?));
        assert_eq!(
            sealed.open((), &retired).unwrap_err(),
            cryptbox::Error::UnknownEncryptionKey(old.id())
        );
        let unavailable = CachedEncryptionKeys::new(None);
        assert_eq!(
            Sealed::<Handle>::seal(&value, (), &unavailable).unwrap_err(),
            Error::KeysUnavailable
        );
        assert_eq!(
            sealed.open((), &unavailable).unwrap_err(),
            Error::KeysUnavailable
        );
        // A later refresh recovers without restarting.
        unavailable.refresh(EncryptionKeyring::new(old, [])?);
        assert_eq!(sealed.open((), &unavailable)?.expose_secret(), "Alice-7");
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
        let normalize = HandleEquality::normalize_query(&invalid).unwrap_err();
        assert_eq!(normalize.to_string(), "blind-index normalization failed");
        assert_eq!(format!("{normalize:?}"), "BlindIndexError");

        // Encoding failure is sanitized at the storage boundary too.
        let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        assert_eq!(
            Sealed::<Handle>::seal(&invalid, (), &keys).unwrap_err(),
            cryptbox::Error::CodecFailed(encode)
        );
        Ok(())
    }

    #[test]
    fn stored_bytes_and_schema_match_their_committed_fixtures() {
        use cryptbox::{schema::Manifest, testing::assert_encoding};

        assert_encoding::<Handle>(&Secret::new("Alice-7".to_owned()), "416c6963652d37");

        let manifest = Manifest::new().field::<Handle>().index::<HandleEquality>();
        assert!(manifest.duplicates().is_empty());
        assert_eq!(
            manifest.to_string(),
            "\
field dcaa3c69-1767-49a1-8476-36555eaf54bf
  codec: handle/1
  padding: none
  record: no
  binding: ff670aba047d77fa
  shred unit: keyring
index 6c0e20d5-cb30-4b84-8dd1-995f872b417c
  field: dcaa3c69-1767-49a1-8476-36555eaf54bf
  bits: 128
  normalizer: handle-lowercase/1
"
        );
    }

    #[test]
    fn an_opened_string_can_be_moved_into_secret() -> Result<(), cryptbox::Error> {
        struct PlainHandle;

        impl Field for PlainHandle {
            const ID: FieldId = Handle::ID;
            const PADDING: Padding = Padding::NONE;
            const RECORD: bool = false;
            type Value = String;
            type Codec = cryptbox::Utf8;
            type Binding = FieldOnly;
            type Indexes = ();
        }

        let keys = EncryptionKeyring::new(EncryptionKey::generate()?, [])?;
        let sealed = Sealed::<PlainHandle>::seal(&"Alice-7".to_owned(), (), &keys)?;
        let secret = Secret::new(sealed.open((), &keys)?);
        assert_eq!(secret.expose_secret(), "Alice-7");
        Ok(())
    }
}
