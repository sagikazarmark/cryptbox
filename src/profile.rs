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
/// as an explicit declaration. Only `id` is required; the other keys are
/// optional and may appear in any order:
///
/// | Key | Default |
/// | --- | --- |
/// | `id` | required: a UUID string literal, see [`Field::ID`] |
/// | `name` | the marker's identifier, e.g. `"UserEmail"` |
/// | `codec` | the value type's [`DefaultCodec`](crate::DefaultCodec): [`Utf8`](crate::Utf8) for `String`, [`Raw`](crate::Raw) for `Vec<u8>` |
/// | `padding` | [`NoPadding`](crate::NoPadding) |
/// | `keys` | [`GlobalKeyContext`](crate::GlobalKeyContext) |
///
/// The value type, field ID, codec, and padding mode are persistent schema.
/// The defaults are permanent, so omitting a key never changes how stored data
/// is read. When converting an existing declaration, keep any codec or padding
/// that differs from the default.
///
/// # Examples
///
/// ```
/// cryptbox::profile! {
///     /// Primary contact address.
///     pub UserEmail: String { id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25" }
/// }
///
/// cryptbox::profile! {
///     pub PaddedEmail: String {
///         id: "b49a65a7-93e6-4b09-8f04-a502578045c1",
///         name: "padded-email",
///         padding: cryptbox::PadToBlock<16>,
///     }
/// }
/// ```
///
/// Types other than `String` and `Vec<u8>` must name their codec:
///
/// ```compile_fail
/// struct Address {
///     city: String,
/// }
///
/// cryptbox::profile! {
///     HomeAddress: Address { id: "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64" }
/// }
/// ```
///
/// Unknown and repeated keys are rejected:
///
/// ```compile_fail
/// cryptbox::profile! {
///     UserEmail: String {
///         id: "ca274e85-63c4-4f7d-a255-2dfecbfe5e25",
///         binding: field_bound,
///     }
/// }
/// ```
#[macro_export]
macro_rules! profile {
    // Keys are collected into fixed slots: [id] [name] [codec] [padding] [keys].
    (@fields $header:tt [] $name:tt $codec:tt $padding:tt $keys:tt
        id: $id:literal $(, $($rest:tt)*)?
    ) => {
        $crate::profile! { @fields $header [$id] $name $codec $padding $keys $($($rest)*)? }
    };
    (@fields $header:tt $id:tt [] $codec:tt $padding:tt $keys:tt
        name: $name:literal $(, $($rest:tt)*)?
    ) => {
        $crate::profile! { @fields $header $id [$name] $codec $padding $keys $($($rest)*)? }
    };
    (@fields $header:tt $id:tt $name:tt [] $padding:tt $keys:tt
        codec: $codec:ty $(, $($rest:tt)*)?
    ) => {
        $crate::profile! { @fields $header $id $name [$codec] $padding $keys $($($rest)*)? }
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt [] $keys:tt
        padding: $padding:ty $(, $($rest:tt)*)?
    ) => {
        $crate::profile! { @fields $header $id $name $codec [$padding] $keys $($($rest)*)? }
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt $padding:tt []
        keys: $keys:ty $(, $($rest:tt)*)?
    ) => {
        $crate::profile! { @fields $header $id $name $codec $padding [$keys] $($($rest)*)? }
    };
    (@fields $header:tt [$($id:tt)+] $name:tt $codec:tt $padding:tt $keys:tt id: $($rest:tt)*) => {
        ::core::compile_error!("duplicate profile key `id`");
    };
    (@fields $header:tt [] $name:tt $codec:tt $padding:tt $keys:tt id: $($rest:tt)*) => {
        ::core::compile_error!("profile key `id` must be a UUID string literal");
    };
    (@fields $header:tt $id:tt [$($name:tt)+] $codec:tt $padding:tt $keys:tt name: $($rest:tt)*) => {
        ::core::compile_error!("duplicate profile key `name`");
    };
    (@fields $header:tt $id:tt [] $codec:tt $padding:tt $keys:tt name: $($rest:tt)*) => {
        ::core::compile_error!("profile key `name` must be a string literal");
    };
    (@fields $header:tt $id:tt $name:tt [$($codec:tt)+] $padding:tt $keys:tt codec: $($rest:tt)*) => {
        ::core::compile_error!("duplicate profile key `codec`");
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt [$($padding:tt)+] $keys:tt padding: $($rest:tt)*) => {
        ::core::compile_error!("duplicate profile key `padding`");
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt $padding:tt [$($keys:tt)+] keys: $($rest:tt)*) => {
        ::core::compile_error!("duplicate profile key `keys`");
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt $padding:tt $keys:tt binding: $($rest:tt)*) => {
        ::core::compile_error!(
            "profile key `binding` was removed: every profile is bound to its field `id`"
        );
    };
    (@fields $header:tt [] $name:tt $codec:tt $padding:tt $keys:tt) => {
        ::core::compile_error!("missing required profile key `id`");
    };
    (@fields
        [$(#[$attribute:meta])* $visibility:vis $profile:ident: $value:ty]
        [$id:literal] [$($name:literal)?] [$($codec:ty)?] [$($padding:ty)?] [$($keys:ty)?]
    ) => {
        $(#[$attribute])*
        $visibility struct $profile;

        impl $crate::Field for $profile {
            const ID: $crate::FieldId = $crate::field_id!($id);
            const NAME: &'static str = $crate::profile!(@name $profile $($name)?);
        }

        impl $crate::EncryptionProfile for $profile {
            type Value = $value;
            type Codec = $crate::profile!(@codec $value; $($codec)?);
            type Padding = $crate::profile!(@padding $($padding)?);
            type Keys = $crate::profile!(@keys $($keys)?);
        }
    };
    (@fields $header:tt $id:tt $name:tt $codec:tt $padding:tt $keys:tt $key:tt $($rest:tt)*) => {
        ::core::compile_error!(::core::concat!(
            "unknown profile key `",
            ::core::stringify!($key),
            "`; expected `id`, `name`, `codec`, `padding`, or `keys`",
        ));
    };
    (@name $profile:ident) => {
        ::core::stringify!($profile)
    };
    (@name $profile:ident $name:literal) => {
        $name
    };
    (@codec $value:ty;) => {
        <$value as $crate::DefaultCodec>::Codec
    };
    (@codec $value:ty; $codec:ty) => {
        $codec
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
        $visibility:vis $profile:ident: $value:ty { $($body:tt)* }
    ) => {
        $crate::profile! {
            @fields [$(#[$attribute])* $visibility $profile: $value] [] [] [] [] []
            $($body)*
        }
    };
}
