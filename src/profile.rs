use crate::{Binding, Codec, KeyContext};

/// Selects the codec, binding policy, and global key context for a value.
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
    /// The process-global key context used by context-less adapters.
    ///
    /// Explicit-provider APIs do not read this context.
    type Keys: KeyContext;
}
