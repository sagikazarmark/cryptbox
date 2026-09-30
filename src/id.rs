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

// Each module declares its identifiers next to what they identify.
pub(crate) use identifier;

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
            "",
        ] {
            assert_eq!(input.parse::<SealId>(), Err(InvalidIdentifier), "{input}");
        }
    }
}
