use zeroize::Zeroizing;

use crate::{CodecError, CodecErrorKind, Secret};

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

    #[cfg(feature = "postcard")]
    fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.bytes.push(byte);
    }

    #[cfg(feature = "json")]
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
/// A codec is a strategy: it does not decide which values use it. A seal names
/// its codec with [`Seal::Codec`](crate::Seal::Codec). Only `String`, `Vec<u8>`,
/// and their [`Secret`] wrappers have a built-in default, which a derived seal
/// uses when it names no codec.
///
/// A seal's codec is part of its persistent schema: ciphertext does not
/// contain a codec identifier or codec version. Changing the emitted bytes or
/// decode compatibility requires migrating existing data. [`Self::ID`] names
/// the representation for the [schema manifest](crate::schema::Manifest), and
/// [`assert_encoding`](crate::testing::assert_encoding) pins its bytes in tests.
///
/// # Implementor obligations
///
/// This interface is extensible; [`crate::Padding`] is a closed set of policies.
/// Encode only the intended value, and decode into an owned value that does not
/// borrow the temporary input. Returned encoding buffers must be
/// [`Zeroizing<Vec<u8>>`]; protect intermediate plaintext allocations on
/// success and error paths too. Wrapping a growable buffer does not erase an old
/// allocation abandoned by reallocation. Preallocate before writing sensitive
/// bytes, or copy into a new zeroizing allocation and wipe the old one before
/// releasing it. Avoid third-party serializers that leave unprotected copies.
///
/// Discard parser/serializer errors that retain input; return only a sanitized
/// [`CodecError`] category without logging plaintext. The decoded `T` belongs to
/// the application: [`crate::Plain`] does not zeroize arbitrary `T`; use
/// [`Secret`] for values that must be erased on drop.
///
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot encode `{T}`",
    label = "not a codec for `{T}`",
    note = "name a codec that implements `Codec<{T}>`, such as `cryptbox::Json`"
)]
pub trait Codec<T>: 'static {
    /// A stable name for this codec's byte representation, such as `"json/1"`.
    ///
    /// The [schema manifest](crate::schema::Manifest) reports it; ciphertext
    /// does not store it. Give every representation its own ID, and change the
    /// ID whenever the emitted bytes or decode compatibility change, so a
    /// manifest snapshot flags the migration. The crate's codecs are `"utf8"`,
    /// `"raw"`, `"json/1"`, and `"postcard/1"`.
    const ID: &'static str;

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

/// The built-in default codec of a value type, which a seal uses when it names
/// none.
///
/// Exactly four types have one, permanently and independent of features:
/// `String` and [`Secret<String>`] use [`Utf8`], and `Vec<u8>` and
/// [`Secret<Vec<u8>>`] use [`Raw`]. A `Secret` value is stored with exactly the
/// same bytes as the value it wraps. The set is closed: a default another crate
/// could declare, or change behind a Cargo feature, would silently change the
/// bytes of every seal that relied on it. Every other type names its codec on
/// the seal, or is stored through a `transparent` seal (ADR-0007).
///
/// Only derive-generated code names this trait.
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no default codec",
    label = "`{Self}` has no built-in codec",
    note = "only `String`, `Vec<u8>`, `Secret<String>`, and `Secret<Vec<u8>>` have one: name the codec with `#[seal(codec = …)]`, such as `cryptbox::Json`; the codec is persistent schema"
)]
pub trait DefaultCodec: Sized + sealed::Sealed {
    /// The codec a seal over this type uses when it names none.
    type Codec: Codec<Self>;
}

mod sealed {
    use crate::Secret;

    pub trait Sealed {}

    impl Sealed for String {}
    impl Sealed for Vec<u8> {}
    impl Sealed for Secret<String> {}
    impl Sealed for Secret<Vec<u8>> {}
}

impl DefaultCodec for String {
    type Codec = Utf8;
}

impl DefaultCodec for Vec<u8> {
    type Codec = Raw;
}

impl DefaultCodec for Secret<String> {
    type Codec = Utf8;
}

impl DefaultCodec for Secret<Vec<u8>> {
    type Codec = Raw;
}

/// Encodes an owned byte vector without transformation.
///
/// Also encodes [`Secret<Vec<u8>>`] with identical bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Raw;

impl Codec<Vec<u8>> for Raw {
    const ID: &'static str = "raw";

    fn encode(value: &Vec<u8>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.clone()))
    }

    fn decode(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
        Ok(bytes.to_vec())
    }
}

impl Codec<Secret<Vec<u8>>> for Raw {
    const ID: &'static str = "raw";

    fn encode(value: &Secret<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Self::encode(value.expose_secret())
    }

    fn decode(bytes: &[u8]) -> Result<Secret<Vec<u8>>, CodecError> {
        <Self as Codec<Vec<u8>>>::decode(bytes).map(Secret::new)
    }
}

/// Encodes an owned string as UTF-8.
///
/// Also encodes [`Secret<String>`] with identical bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Utf8;

impl Codec<String> for Utf8 {
    const ID: &'static str = "utf8";

    fn encode(value: &String) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<String, CodecError> {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| CodecError::new(CodecErrorKind::InvalidUtf8))
    }
}

impl Codec<Secret<String>> for Utf8 {
    const ID: &'static str = "utf8";

    fn encode(value: &Secret<String>) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Self::encode(value.expose_secret())
    }

    fn decode(bytes: &[u8]) -> Result<Secret<String>, CodecError> {
        <Self as Codec<String>>::decode(bytes).map(Secret::new)
    }
}

/// Encodes Serde values as JSON.
///
/// Available with the `json` feature (which implies `serde`). Its [`Codec::ID`]
/// is `"json/1"`. Floats decode to exactly the value that was encoded.
///
/// The value type's Serde representation is persistent schema. A serde
/// attribute change such as `rename_all` changes the stored bytes of every seal
/// that uses the type, and a renamed field fails to decode or silently takes its
/// default. Pin each seal's bytes with
/// [`assert_encoding`](crate::testing::assert_encoding).
#[cfg(feature = "json")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Json;

#[cfg(feature = "json")]
impl<T> Codec<T> for Json
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    const ID: &'static str = "json/1";

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
/// Available with the `postcard` feature (which implies `serde`). Its
/// [`Codec::ID`] is `"postcard/1"`.
///
/// Postcard is positional: it stores no field or variant names. Reordering
/// struct fields or enum variants, or changing an integer type, decodes existing
/// bytes into wrong values without an error. Serde attribute changes such as
/// `rename_all` can change the stored bytes as well, for every seal that uses
/// the value type. Pin each seal's bytes with
/// [`assert_encoding`](crate::testing::assert_encoding).
#[cfg(feature = "postcard")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Postcard;

#[cfg(feature = "postcard")]
impl<T> Codec<T> for Postcard
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    const ID: &'static str = "postcard/1";

    fn encode(value: &T) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        let bytes = ZeroizingByteBuffer::new();

        postcard::to_extend(value, bytes)
            .map(ZeroizingByteBuffer::into_bytes)
            .map_err(|_| CodecError::new(CodecErrorKind::Encoding))
    }

    fn decode(bytes: &[u8]) -> Result<T, CodecError> {
        // `from_bytes` ignores trailing bytes, so a value followed by anything
        // else (such as padding that was never removed) would decode silently.
        match postcard::take_from_bytes(bytes) {
            Ok((value, [])) => Ok(value),
            _ => Err(CodecError::new(CodecErrorKind::Decoding)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These defaults are persistent schema: changing one would silently misread
    // every value a seal sealed without naming its codec.
    #[test]
    fn the_built_in_types_have_permanent_default_codecs() {
        fn assert_default<T: DefaultCodec<Codec = C>, C>() {}

        assert_default::<String, Utf8>();
        assert_default::<Vec<u8>, Raw>();
        assert_default::<Secret<String>, Utf8>();
        assert_default::<Secret<Vec<u8>>, Raw>();
    }
}
