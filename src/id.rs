use std::fmt;

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates an identifier from its canonical 16-byte representation.
            ///
            /// The bytes are not checked: stored IDs are read through it, and
            /// the format does not reserve the nil UUID. Declare an ID with
            /// [`Self::from_u128`] or its macro, which reject the nil UUID.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Creates an identifier from a UUID's 128 bits, most significant first.
            ///
            /// `0x0b6f3c2a_8e41_4d57_a9c3_5e1f2d7b8a64` names the same identifier
            /// as the literal `"0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64"`.
            ///
            /// # Panics
            ///
            /// Panics for the nil UUID, which fails the build in a `const`.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self($crate::id::non_nil(value.to_be_bytes()))
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

            /// Parses the hyphenated form, rejecting the nil UUID as the ID macros do.
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match $crate::id::parse_uuid(value) {
                    Ok(bytes) if !$crate::id::is_nil(&bytes) => Ok(Self(bytes)),
                    _ => Err($crate::InvalidIdentifier),
                }
            }
        }
    };
}

// Each module declares its identifiers next to what they identify.
pub(crate) use identifier;

/// The supplied text is not a hyphenated UUID, or is the nil UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidIdentifier;

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier must be a hyphenated, non-nil UUID")
    }
}

impl std::error::Error for InvalidIdentifier {}

/// Returns `bytes`, failing const evaluation for the nil UUID. Not public API:
/// the ID macros call it, so a nil literal fails the build.
#[doc(hidden)]
#[must_use]
pub const fn non_nil(bytes: [u8; 16]) -> [u8; 16] {
    assert!(
        !is_nil(&bytes),
        "an ID must not be the nil UUID: generate a fresh one"
    );

    bytes
}

/// Reports whether `bytes` is the nil UUID. Not public API: `assert_unique_ids!`
/// calls it.
#[doc(hidden)]
#[must_use]
pub const fn is_nil(bytes: &[u8; 16]) -> bool {
    let mut index = 0;
    while index < 16 {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }

    true
}

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

#[cfg(test)]
mod tests {
    use super::InvalidIdentifier;
    use crate::SealId;

    const HYPHENATED: &str = "0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64";

    #[test]
    fn parses_and_displays_the_hyphenated_form() {
        let id: SealId = HYPHENATED.parse().unwrap();

        assert_eq!(id, crate::seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64"));
        assert_eq!(
            id,
            SealId::from_u128(0x0b6f_3c2a_8e41_4d57_a9c3_5e1f_2d7b_8a64)
        );
        assert_eq!(id.to_string(), HYPHENATED);
        assert_eq!(
            "0B6F3C2A-8E41-4D57-A9C3-5E1F2D7B8A64".parse::<SealId>(),
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
            "00000000-0000-0000-0000-000000000000",
            "",
        ] {
            assert_eq!(input.parse::<SealId>(), Err(InvalidIdentifier), "{input}");
        }
    }
}
