use crate::{Binding, Codec, KeyContext, Padding};

/// Selects the codec, binding, padding, and global key context for a value.
///
/// These associated types define persistent schema. The ciphertext envelope
/// does not store a profile or codec identifier, so changing them can make
/// existing values undecodable or alter their authenticated binding. Make such
/// changes through an explicit data migration.
pub trait EncryptionProfile<T>: Sized + 'static {
    /// The codec used before encryption and after decryption.
    ///
    /// Its byte representation must remain compatible with stored ciphertext.
    type Codec: Codec<T>;
    /// The authenticated binding policy, which must remain stable for stored data.
    type Binding: Binding;
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
/// This generates the same [`Field`](crate::Field) and [`EncryptionProfile`]
/// implementations as an explicit declaration. The binding mode is always
/// required: use `field_bound` to bind ciphertext to the declared field ID, or
/// `unbound` to explicitly opt out. Omitting `padding` selects
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
///         binding: field_bound,
///         padding: cryptbox::PadToBlock<16>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! profile {
    (@binding $profile:ident, field_bound) => {
        $crate::FieldBound<$profile>
    };
    (@binding $profile:ident, unbound) => {
        $crate::Unbound
    };
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
            codec: $codec:ty,
            binding: $binding:ident
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

        impl $crate::EncryptionProfile<$value> for $profile {
            type Codec = $codec;
            type Binding = $crate::profile!(@binding Self, $binding);
            type Padding = $crate::profile!(@padding $($padding)?);
            type Keys = $crate::profile!(@keys $($keys)?);
        }
    };
}
