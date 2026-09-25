use zeroize::Zeroizing;

use crate::{CodecError, CodecErrorKind};

#[cfg(any(feature = "json", feature = "postcard"))]
struct ZeroizingByteBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

#[cfg(any(feature = "json", feature = "postcard"))]
impl ZeroizingByteBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.bytes.push(byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.bytes.extend_from_slice(bytes);
    }

    fn reserve(&mut self, additional: usize) {
        let required_capacity = self
            .bytes
            .len()
            .checked_add(additional)
            .expect("plaintext buffer capacity overflow");

        if required_capacity <= self.bytes.capacity() {
            return;
        }

        let new_capacity = self
            .bytes
            .capacity()
            .saturating_mul(2)
            .max(required_capacity)
            .max(8);
        let mut replacement = Zeroizing::new(Vec::with_capacity(new_capacity));
        replacement.extend_from_slice(&self.bytes);

        // Keep the old allocation alive until the copy is complete, then wipe it
        // before its storage is returned to the allocator.
        drop(std::mem::replace(&mut self.bytes, replacement));
    }
}

#[cfg(feature = "postcard")]
impl Extend<u8> for ZeroizingByteBuffer {
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        for byte in iter {
            self.push(byte);
        }
    }
}

#[cfg(feature = "json")]
impl std::io::Write for ZeroizingByteBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encodes and decodes typed values independently from encryption.
///
/// A profile's codec is part of its persistent schema: ciphertext does not
/// contain a codec identifier or codec version. Changing the emitted bytes or
/// decode compatibility requires migrating existing data.
///
/// # Implementor obligations
///
/// This interface is extensible; [`crate::Binding`] and [`crate::Padding`] are
/// sealed policies. Encode only the intended value, and decode into an owned
/// value that does not borrow the temporary input. Returned encoding buffers
/// must be [`Zeroizing<Vec<u8>>`]; protect intermediate plaintext allocations on
/// success and error paths too. Wrapping a growable buffer does not erase an old
/// allocation abandoned by reallocation. Preallocate before writing sensitive
/// bytes, or copy into a new zeroizing allocation and wipe the old one before
/// releasing it. Avoid third-party serializers that leave unprotected copies.
///
/// Discard parser/serializer errors that retain input; return only a sanitized
/// [`CodecError`] category without logging plaintext. The decoded `T` belongs to
/// the application: [`crate::Encrypted`] does not zeroize arbitrary `T`. A profile
/// over [`crate::Secret<String>`] needs a codec for that exact type; [`Utf8`]
/// implements only `Codec<String>`, not arbitrary secret wrappers.
///
/// See the development [custom-profile recipe] and canonical [ownership explanation].
///
/// [custom-profile recipe]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/custom-profile.md
/// [ownership explanation]: https://github.com/sagikazarmark/cryptbox/blob/main/docs/concepts.md#plaintext-and-key-ownership
pub trait Codec<T>: Sized + 'static {
    /// Encodes `value` into an owned, zeroizing plaintext buffer.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the value cannot be encoded.
    fn encode(value: &T) -> Result<Zeroizing<Vec<u8>>, CodecError>;

    /// Decodes a value that does not borrow from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the bytes are invalid for this codec.
    fn decode(bytes: &[u8]) -> Result<T, CodecError>;
}

/// Encodes an owned byte vector without transformation.
#[derive(Clone, Copy, Debug, Default)]
pub struct Raw;

impl Codec<Vec<u8>> for Raw {
    fn encode(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.clone()))
    }

    fn decode(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
        Ok(bytes.to_vec())
    }
}

/// Encodes an owned string as UTF-8.
#[derive(Clone, Copy, Debug, Default)]
pub struct Utf8;

impl Codec<String> for Utf8 {
    fn encode(value: &String) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<String, CodecError> {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))
    }
}

/// Encodes Serde values as JSON.
///
/// Available with the `json` feature (which implies `serde`).
#[cfg(feature = "json")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Json;

#[cfg(feature = "json")]
impl<T> Codec<T> for Json
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn encode(value: &T) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let mut bytes = ZeroizingByteBuffer::new();

        serde_json::to_writer(&mut bytes, value)
            .map(|()| bytes.into_bytes())
            .map_err(|_| CodecError::new(CodecErrorKind::Encoding))
    }

    fn decode(bytes: &[u8]) -> Result<T, CodecError> {
        serde_json::from_slice(bytes).map_err(|_| CodecError::new(CodecErrorKind::Decoding))
    }
}

/// Encodes Serde values with Postcard.
///
/// Available with the `postcard` feature (which implies `serde`).
#[cfg(feature = "postcard")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Postcard;

#[cfg(feature = "postcard")]
impl<T> Codec<T> for Postcard
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn encode(value: &T) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let bytes = ZeroizingByteBuffer::new();

        postcard::to_extend(value, bytes)
            .map(ZeroizingByteBuffer::into_bytes)
            .map_err(|_| CodecError::new(CodecErrorKind::Encoding))
    }

    fn decode(bytes: &[u8]) -> Result<T, CodecError> {
        postcard::from_bytes(bytes).map_err(|_| CodecError::new(CodecErrorKind::Decoding))
    }
}
