use std::fmt;

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an identifier from its canonical 16-byte representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Creates an identifier from a UUID's 128 bits, most significant first.
            ///
            /// `0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64` names the same identifier
            /// as the literal `"0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64"`.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self(value.to_be_bytes())
            }

            /// Returns the canonical 16-byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&::uuid::Uuid::from_bytes(self.0).hyphenated(), formatter)
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!("{}", self))
                    .finish()
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::InvalidIdentifier;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                $crate::id::parse_uuid(value).map(Self)
            }
        }
    };
}

// Shared with `key`, which declares its key-generation IDs next to the keys.
pub(crate) use identifier;

identifier!(FieldId, "A stable logical encrypted-field identifier.");
identifier!(IndexId, "A stable logical blind-index identifier.");
identifier!(
    PartId,
    "A stable binding-part identifier, independent of Rust names."
);

/// Identifies a complete encryption-suite construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SuiteId(u8);

impl SuiteId {
    /// Creates a suite identifier from its wire value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the suite's wire value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for SuiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A 64-bit fingerprint of a binding's shape: its part IDs, kinds, and roles,
/// and whether it binds a record.
///
/// Every ciphertext header carries the fingerprint of the shape it was sealed
/// with; a field-only binding has the empty shape. It is diagnostic only: a reader always takes the expected shape
/// from its own field, and reports [`Error::BindingMismatch`](crate::Error::BindingMismatch) when the stored
/// fingerprint disagrees. See the [wire format].
///
#[doc = concat!(
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#shape-fingerprint",
)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ShapeFingerprint([u8; 8]);

impl ShapeFingerprint {
    /// Creates a fingerprint from its stored 8-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Returns the stored 8-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for ShapeFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

impl fmt::Debug for ShapeFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ShapeFingerprint")
            .field(&format_args!("{self}"))
            .finish()
    }
}

/// The supplied text is not a canonical hyphenated UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidIdentifier;

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier must be a hyphenated UUID")
    }
}

impl std::error::Error for InvalidIdentifier {}

// Accepts only the hyphenated form: `try_parse` also takes simple, braced, and URN
// forms, which all differ from it in length.
pub(crate) fn parse_uuid(value: &str) -> Result<[u8; 16], InvalidIdentifier> {
    if value.len() != 36 {
        return Err(InvalidIdentifier);
    }

    uuid::Uuid::try_parse(value)
        .map(uuid::Uuid::into_bytes)
        .map_err(|_| InvalidIdentifier)
}

/// Creates a [`FieldId`](crate::FieldId) from a UUID literal.
#[macro_export]
macro_rules! field_id {
    ($value:literal) => {{
        const ID: $crate::FieldId =
            $crate::FieldId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}

/// Creates an [`IndexId`](crate::IndexId) from a UUID literal.
#[macro_export]
macro_rules! index_id {
    ($value:literal) => {{
        const ID: $crate::IndexId =
            $crate::IndexId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}

/// Creates a [`PartId`](crate::PartId) from a UUID literal.
#[macro_export]
macro_rules! part_id {
    ($value:literal) => {{
        const ID: $crate::PartId =
            $crate::PartId::from_bytes($crate::__private::uuid::uuid!($value).into_bytes());
        ID
    }};
}

#[cfg(test)]
mod tests {
    use super::{FieldId, InvalidIdentifier};

    const HYPHENATED: &str = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64";

    #[test]
    fn parses_and_displays_the_hyphenated_form() {
        let id: FieldId = HYPHENATED.parse().unwrap();

        assert_eq!(id, crate::field_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64"));
        assert_eq!(
            id,
            FieldId::from_u128(0x0b6f_3c2a_8e41_4d57_a9c3_5e1f_2d7b_8a64)
        );
        assert_eq!(id.to_string(), HYPHENATED);
        assert_eq!(
            "0B6F3C2A-8E41-4D57-A9C3-5E1F2D7B8A64".parse::<FieldId>(),
            Ok(id)
        );
    }

    #[test]
    fn rejects_every_other_form() {
        for input in [
            "0b6f3c2a8e414d57a9c35e1f2d7b8a64",
            "{0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64}",
            "urn:uuid:0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64",
            "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a6z",
            "0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64",
            "",
        ] {
            assert_eq!(input.parse::<FieldId>(), Err(InvalidIdentifier), "{input}");
        }
    }
}
