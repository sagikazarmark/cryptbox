use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Plaintext with zeroization on drop and explicit access semantics.
///
/// Drop invokes `T`'s [`Zeroize`] implementation. Cloning creates a separate `T`
/// with its own lifetime; it does not share a single erasure boundary. This cannot
/// erase previous copies, superseded allocations, or OS copies. Read the value
/// with [`Self::expose_secret`]. For an opened `String`, use
/// `Secret::new(sealed.open(&keys)?)`.
/// A seal can also take `Secret<String>` or `Secret<Vec<u8>>` as its value type: their
/// default codecs ([`crate::Utf8`], [`crate::Raw`]) write the same bytes.
/// See the [custom-seal example] and [ownership reference].
///
#[doc = concat!(
    "[custom-seal example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/examples/custom_seal/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/v", env!("CARGO_PKG_VERSION"), "/docs/guide.md#ownership-and-erasure",
)]
pub struct Secret<T: Zeroize> {
    value: Zeroizing<T>,
}

impl<T: Zeroize> Secret<T> {
    /// Wraps plaintext that will be zeroized on drop.
    pub fn new(value: T) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    /// Explicitly exposes the plaintext value.
    #[must_use]
    pub fn expose_secret(&self) -> &T {
        &self.value
    }
}

impl<T: Clone + Zeroize> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self::new((*self.value).clone())
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}
