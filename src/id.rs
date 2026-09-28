use std::{fmt, str::FromStr};

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

            /// Parses a UUID literal and can be evaluated at compile time.
            ///
            /// # Panics
            ///
            /// Panics during constant evaluation when `value` is not a
            /// hyphenated UUID string.
            #[doc(hidden)]
            #[must_use]
            pub const fn from_uuid_literal(value: &str) -> Self {
                Self(parse_uuid_literal(value))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_uuid(formatter, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!("{}", self))
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = InvalidIdentifier;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_uuid(value).map(Self)
            }
        }
    };
}

identifier!(FieldId, "A stable logical encrypted-field identifier.");
identifier!(KeyId, "An opaque encryption-key generation identifier.");
identifier!(IndexId, "A stable logical blind-index identifier.");
identifier!(
    PartId,
    "A stable binding-part identifier, independent of Rust names."
);
identifier!(
    IndexKeyId,
    "An opaque blind-index-key generation identifier."
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
/// A scoped ciphertext header carries the fingerprint of the shape it was
/// sealed with. It is diagnostic only: a reader always takes the expected shape
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

const fn parse_uuid_literal(value: &str) -> [u8; 16] {
    let input = value.as_bytes();

    assert!(input.len() == 36, "identifier must be a hyphenated UUID");

    let mut output = [0_u8; 16];
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index < 36 {
        if input_index == 8 || input_index == 13 || input_index == 18 || input_index == 23 {
            assert!(input[input_index] == b'-', "identifier has invalid hyphens");
            input_index += 1;
        } else {
            let high = hex_nibble(input[input_index]);
            let low = hex_nibble(input[input_index + 1]);
            output[output_index] = (high << 4) | low;
            input_index += 2;
            output_index += 1;
        }
    }

    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("identifier contains non-hexadecimal characters"),
    }
}

fn parse_uuid(value: &str) -> Result<[u8; 16], InvalidIdentifier> {
    let input = value.as_bytes();

    if input.len() != 36 {
        return Err(InvalidIdentifier);
    }

    let mut output = [0_u8; 16];
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index < input.len() {
        if matches!(input_index, 8 | 13 | 18 | 23) {
            if input[input_index] != b'-' {
                return Err(InvalidIdentifier);
            }
            input_index += 1;
        } else {
            let high = parse_hex_nibble(input[input_index])?;
            let low = parse_hex_nibble(input[input_index + 1])?;
            output[output_index] = (high << 4) | low;
            input_index += 2;
            output_index += 1;
        }
    }

    Ok(output)
}

fn parse_hex_nibble(value: u8) -> Result<u8, InvalidIdentifier> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(InvalidIdentifier),
    }
}

fn write_uuid(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 16]) -> fmt::Result {
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            formatter.write_str("-")?;
        }
        write!(formatter, "{byte:02x}")?;
    }

    Ok(())
}

/// Creates a [`FieldId`](crate::FieldId) from a UUID literal.
#[macro_export]
macro_rules! field_id {
    ($value:literal) => {{
        const ID: $crate::FieldId = $crate::FieldId::from_uuid_literal($value);
        ID
    }};
}

/// Creates a [`KeyId`](crate::KeyId) from a UUID literal.
#[macro_export]
macro_rules! key_id {
    ($value:literal) => {{
        const ID: $crate::KeyId = $crate::KeyId::from_uuid_literal($value);
        ID
    }};
}

/// Creates an [`IndexId`](crate::IndexId) from a UUID literal.
#[macro_export]
macro_rules! index_id {
    ($value:literal) => {{
        const ID: $crate::IndexId = $crate::IndexId::from_uuid_literal($value);
        ID
    }};
}

/// Creates an [`IndexKeyId`](crate::IndexKeyId) from a UUID literal.
#[macro_export]
macro_rules! index_key_id {
    ($value:literal) => {{
        const ID: $crate::IndexKeyId = $crate::IndexKeyId::from_uuid_literal($value);
        ID
    }};
}

/// Creates a [`PartId`](crate::PartId) from a UUID literal.
#[macro_export]
macro_rules! part_id {
    ($value:literal) => {{
        const ID: $crate::PartId = $crate::PartId::from_uuid_literal($value);
        ID
    }};
}
