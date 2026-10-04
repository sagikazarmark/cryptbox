//! Fixtures shared by the fuzz targets: fixed keys, seals, and blind-index
//! specs, and the error taxonomy each stored-format operation may report.
//!
//! The keys are fixed so a crash reproduces from its input alone. Sealing still
//! draws a fresh nonce, which changes no property the targets assert.

use cryptbox::{
    BlindIndexError, BlindIndexKey, BlindIndexKeyring, BlindIndexSpec, EncryptionKey,
    EncryptionKeyring, Error, IndexId, Padding, Raw, Seal, SealId,
};
use zeroize::Zeroizing;

/// The fixed encryption keyring: one current key and one previous key.
///
/// # Panics
///
/// Never: the fixture key IDs are distinct.
#[must_use]
pub fn encryption_keys() -> EncryptionKeyring {
    EncryptionKeyring::new(
        EncryptionKey::new(
            cryptbox::key_id!("11111111-2222-4333-8444-555555555555"),
            [0x11; 32],
        ),
        [EncryptionKey::new(
            cryptbox::key_id!("66666666-7777-4888-8999-aaaaaaaaaaaa"),
            [0x66; 32],
        )],
    )
    .expect("the fixture key IDs are distinct")
}

/// The fixed blind-index keyring: one current key and one previous key.
///
/// # Panics
///
/// Never: the fixture key IDs are distinct.
#[must_use]
pub fn blind_index_keys() -> BlindIndexKeyring {
    BlindIndexKeyring::new(
        BlindIndexKey::new(
            cryptbox::index_key_id!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
            [0x22; 32],
        ),
        [BlindIndexKey::new(
            cryptbox::index_key_id!("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"),
            [0x33; 32],
        )],
    )
    .expect("the fixture key IDs are distinct")
}

/// Raw bytes sealed without padding.
pub struct Unpadded;

impl Seal for Unpadded {
    const ID: SealId = cryptbox::seal_id!("12345678-1234-4234-8234-1234567890ab");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
}

/// Raw bytes padded to 16-byte blocks, so the padded flag and unpadding run.
pub struct Padded;

impl Seal for Padded {
    const ID: SealId = cryptbox::seal_id!("23456789-2345-4345-8345-234567890abc");
    const PADDING: Padding = Padding::block(16);
    type Value = Vec<u8>;
    type Codec = Raw;
}

/// Declares an identity-normalized blind-index spec over [`Unpadded`].
macro_rules! spec {
    ($name:ident, $id:literal, $bits:literal) => {
        #[doc = concat!("An identity-normalized ", stringify!($bits), "-bit index over [`Unpadded`].")]
        pub struct $name;

        impl BlindIndexSpec for $name {
            type Seal = Unpadded;
            const ID: IndexId = cryptbox::index_id!($id);
            const BITS: u16 = $bits;
            const NORMALIZER: &'static str = "identity/1";
            type Query = [u8];

            fn normalize_query(query: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
                Ok(Zeroizing::new(query.to_vec()))
            }

            fn normalize_value(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
                Self::normalize_query(value)
            }
        }
    };
}

// The smallest, a non-byte-aligned, a byte-aligned, and the largest precision.
spec!(Bits1, "abcdefab-cdef-4def-8def-abcdefab0001", 1);
spec!(Bits13, "abcdefab-cdef-4def-8def-abcdefab0013", 13);
spec!(Bits32, "abcdefab-cdef-4def-8def-abcdefab0032", 32);
spec!(Bits256, "abcdefab-cdef-4def-8def-abcdefab0256", 256);

/// Reports whether the unused low bits of the final byte of a `bits`-bit
/// stored index are zero, as docs/wire-format.md#stored-layout requires.
#[must_use]
pub fn is_canonical(stored: &[u8], bits: u16) -> bool {
    let unused = match bits % 8 {
        0 => 0,
        retained => u8::MAX >> retained,
    };

    stored.last().is_some_and(|last| last & unused == 0)
}

/// Asserts that `error` is the one parsing `stored` as a blind index reports:
/// `UnsupportedBlindIndexVersion` for a full header of another version, and
/// `InvalidBlindIndex` otherwise.
///
/// # Panics
///
/// Panics for any other error.
pub fn assert_index_parse_error(stored: &[u8], error: &Error) {
    // The version byte, the index key ID, and the bit count.
    const HEADER_LEN: usize = 19;

    let expected = match stored.first() {
        Some(&version) if stored.len() >= HEADER_LEN && version != 2 => {
            Error::UnsupportedBlindIndexVersion(version)
        }
        _ => Error::InvalidBlindIndex,
    };
    assert_eq!(error, &expected);
}

/// Asserts that `error` is one structural parsing of an envelope may report.
///
/// # Panics
///
/// Panics for any other error.
pub fn assert_parse_error(error: &Error) {
    assert!(
        matches!(
            error,
            Error::NotCiphertext
                | Error::InvalidEnvelope
                | Error::UnsupportedFormatVersion(_)
                | Error::UnsupportedSuite(_)
                | Error::UnsupportedFlags(_)
                | Error::MessageTooLong
        ),
        "unexpected envelope parsing error: {error:?}"
    );
}

/// Asserts that `error` is one opening an envelope that did not come from the
/// writer may report: never one only authenticated plaintext can cause, such as
/// invalid padding or a codec failure.
///
/// # Panics
///
/// Panics for any other error.
pub fn assert_forgery_error(error: &Error) {
    assert!(
        matches!(
            error,
            Error::AuthenticationFailed | Error::ContextMismatch | Error::UnknownEncryptionKey(_)
        ),
        "unexpected error opening an unauthenticated envelope: {error:?}"
    );
}
