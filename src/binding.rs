use crate::FieldId;

/// Declares the identity and diagnostic name of a logical encrypted field.
///
/// Every ciphertext and blind index is bound to exactly one field ID: decryption
/// under a different field fails authentication. Generate a unique ID for each
/// logical field, keep it stable across Rust and database renames, and never reuse
/// it for a different field. Changing the ID makes existing ciphertext fail
/// authentication. Declaring the same ID on several types deliberately makes them
/// the same logical field. The name is non-secret diagnostic metadata: it need not
/// be unique or stable and does not participate in cryptographic operations.
///
/// For blind indexes, the field domain-separates derivation; it does not
/// authenticate the stored index representation. Field binding does not prevent
/// substitution between rows of the same field. Compare decrypted candidate
/// plaintext for lookup, and recompute indexes separately when stored-index
/// consistency is required.
pub trait Field: Sized + 'static {
    /// The stable identifier, independent of Rust and database names.
    const ID: FieldId;

    /// A human-readable name for caller-owned diagnostics.
    ///
    /// The name may reveal application schema and must not contain plaintext,
    /// record-specific data, or key material.
    const NAME: &'static str;
}

/// Canonical field-binding bytes passed to the cryptographic core.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindingDomain {
    encoded: [u8; 17],
}

impl BindingDomain {
    // The tag and UUID bytes are persistent KDF/AAD inputs, independent of
    // diagnostic names. Tag `00` is reserved. See ../docs/wire-format.md#binding.
    const FIELD_TAG: u8 = 1;

    pub(crate) fn field<F: Field>() -> Self {
        let mut encoded = [0_u8; 17];
        encoded[0] = Self::FIELD_TAG;
        encoded[1..].copy_from_slice(F::ID.as_bytes());

        Self { encoded }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}
