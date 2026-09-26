use crate::{Codec, Field, KeyContext, Padding};

/// Selects the value type, codec, padding, and global key context for a field.
///
/// A profile is a [`Field`]: every value it encrypts is bound to the field ID.
/// The value type, codec representation, field ID, and presence or absence of
/// padding define persistent schema. The ciphertext envelope does not store a
/// profile or codec identifier, so incompatible changes require an explicit data
/// migration. Changing the key-context implementation alone does not change
/// stored schema; it must still resolve the same immutable key-ID/material pairs
/// needed by stored data. Explicit-provider APIs do not use the profile's key
/// context.
///
/// Applications can implement this trait, [`Codec`], index normalizers, and key
/// providers. [`Padding`] is sealed to built-in policies; row/tenant binding is
/// future work. The codec must implement `Codec<Self::Value>` for the exact
/// application type, including any secret wrapper. See the
/// [custom-profile example] and [ownership reference].
///
#[doc = concat!(
    "[custom-profile example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_profile/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md",
)]
pub trait EncryptionProfile: Field {
    /// The plaintext application type encrypted under this profile.
    type Value;
    /// The codec used before encryption and after decryption.
    ///
    /// Its byte representation must remain compatible with stored ciphertext.
    type Codec: Codec<Self::Value>;
    /// The padding policy applied between the codec and encryption.
    ///
    /// Enabling or disabling padding for stored ciphertext requires an explicit
    /// migration. Parameters of an already-padded policy may change freely.
    type Padding: Padding;
    /// The process-global key context used by context-less adapters.
    ///
    /// Explicit-provider APIs do not read this context.
    type Keys: KeyContext;
}

/// Declares a marker type and its encrypted-field policy.
///
/// This generates the same [`Field`] and [`EncryptionProfile`] implementations
/// as an explicit declaration. Omitting `padding` selects
/// [`NoPadding`](crate::NoPadding), and omitting `keys` selects
/// [`GlobalKeyContext`](crate::GlobalKeyContext).
///
/// # Example
///
/// ```
/// cryptbox::profile! {
///     pub UserEmail: String {
///         id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
///         name: "user-email",
///         codec: cryptbox::Utf8,
///         padding: cryptbox::PadToBlock<16>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! profile {
    (@keys) => {
        $crate::GlobalKeyContext
    };
    (@keys $keys:ty) => {
        $keys
    };
    (@padding) => {
        $crate::NoPadding
    };
    (@padding $padding:ty) => {
        $padding
    };
    (
        $(#[$attribute:meta])*
        $visibility:vis $profile:ident: $value:ty {
            id: $id:literal,
            name: $name:literal,
            codec: $codec:ty
            $(, padding: $padding:ty)?
            $(, keys: $keys:ty)?
            $(,)?
        }
    ) => {
        $(#[$attribute])*
        $visibility struct $profile;

        impl $crate::Field for $profile {
            const ID: $crate::FieldId = $crate::field_id!($id);
            const NAME: &'static str = $name;
        }

        impl $crate::EncryptionProfile for $profile {
            type Value = $value;
            type Codec = $codec;
            type Padding = $crate::profile!(@padding $($padding)?);
            type Keys = $crate::profile!(@keys $($keys)?);
        }
    };
}
