use crate::{Codec, FieldId, Padding};

/// Declares a logical encrypted field: its identity, value type, codec, and padding.
///
/// A field is a marker type, separate from the application's value type. The
/// value type (`String`, `Address`, `Secret<String>`) says how it encodes; the
/// field says where it is stored. One value type can back several fields, such as
/// `HomeAddress` and `BillingAddress` over one `Address`, and each field has its
/// own ID so their ciphertext cannot be swapped.
///
/// Every ciphertext and blind index is bound to exactly one field ID: decryption
/// under a different field fails authentication. Generate a unique ID for each
/// logical field, keep it stable across Rust and database renames, and never reuse
/// it for a different field. Changing the ID makes existing ciphertext fail
/// authentication. Declaring the same ID on several types deliberately makes them
/// the same logical field.
///
/// The value type, codec representation, and field ID define persistent schema.
/// The ciphertext envelope does not store a codec identifier, so incompatible
/// changes require an explicit data migration. Padding is write policy instead:
/// the envelope records whether a value is padded. See [`crate::schema`] and
/// [`crate::testing`] for CI checks of this schema.
///
/// For blind indexes, the field domain-separates derivation; it does not
/// authenticate the stored index representation. Field binding does not prevent
/// substitution between rows of the same field. Compare decrypted candidate
/// plaintext for lookup, and recompute indexes separately when stored-index
/// consistency is required.
///
/// # Examples
///
/// ```
/// use cryptbox::{Field, FieldId, Padding, Plaintext};
///
/// /// Primary contact address.
/// pub struct UserEmail;
///
/// impl Field for UserEmail {
///     const ID: FieldId = cryptbox::field_id!("ca274e85-63c4-4f7d-a255-2dfecbfe5e25");
///     const PADDING: Padding = Padding::NONE;
///     type Value = String;
///     type Codec = <String as Plaintext>::Codec;
/// }
/// ```
///
/// With the `derive` feature, `#[derive(Field)]` writes exactly this impl from
/// `#[cryptbox(id = "ca274e85-63c4-4f7d-a255-2dfecbfe5e25", value = String)]`.
///
/// A value type without a [`Plaintext`](crate::Plaintext) implementation has no
/// default codec; implement `Plaintext` for it or name an explicit codec:
///
/// ```compile_fail,E0277
/// use cryptbox::{Field, FieldId, Padding, Plaintext};
///
/// struct Address {
///     city: String,
/// }
///
/// struct HomeAddress;
///
/// impl Field for HomeAddress {
///     const ID: FieldId = cryptbox::field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
///     const PADDING: Padding = Padding::NONE;
///     type Value = Address;
///     type Codec = <Address as Plaintext>::Codec;
/// }
/// ```
///
/// See the [custom-field example] and [ownership reference].
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub trait Field: 'static {
    /// The stable identifier, independent of Rust and database names.
    const ID: FieldId;

    /// The padding policy applied to new values between the codec and encryption.
    ///
    /// This describes how values are written, not how they are read: the
    /// envelope records whether its payload is padded. Changing the policy keeps
    /// format 2 values readable, and re-encryption rewrites them with it. Format 1
    /// values are read with the current policy, so re-encrypt them first; see
    /// [`Padding`].
    const PADDING: Padding;

    /// The plaintext application type stored in this field.
    type Value;

    /// The codec used before encryption and after decryption.
    ///
    /// Its byte representation must remain compatible with stored ciphertext.
    /// Use `<Self::Value as Plaintext>::Codec` for the value type's default codec.
    type Codec: Codec<Self::Value>;
}

/// Canonical field-binding bytes passed to the cryptographic core.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingDomain {
    encoded: [u8; 17],
}

impl BindingDomain {
    // The tag and UUID bytes are persistent KDF/AAD inputs, independent of
    // Rust names. Tag `00` is reserved. See ../docs/wire-format.md#binding.
    const FIELD_TAG: u8 = 1;

    pub(crate) fn field(id: FieldId) -> Self {
        let mut encoded = [0_u8; 17];
        encoded[0] = Self::FIELD_TAG;
        encoded[1..].copy_from_slice(id.as_bytes());

        Self { encoded }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}
