use zeroize::Zeroizing;

use crate::Error;

/// Expands encoded plaintext before encryption to hide its exact length.
///
/// A field selects its policy with [`Field::PADDING`](crate::Field::PADDING):
/// [`Padding::NONE`], [`Padding::block`], or [`Padding::length`]. The
/// representation is private, so applications cannot define another policy.
///
/// A policy describes how new values are written; it is not persistent schema.
/// The ciphertext envelope records whether its payload is padded, and readers
/// remove padding only when that authenticated flag is set. A field can enable or
/// disable padding, or change its parameters, without making values unreadable;
/// re-encryption rewrites a value whose flag disagrees with the current policy.
/// Format 1 ciphertext does not record padding and is read with the current
/// policy, so re-encrypt it before changing the policy; see the [format 1 rules].
///
/// Padded values use ISO/IEC 7816-4 padding: a `0x80` marker followed by zero
/// bytes. See the [custom-field example] and [ownership reference].
///
/// Invalid parameters in a constant are rejected at compile time:
///
/// ```compile_fail,E0080
/// const PADDING: cryptbox::Padding = cryptbox::Padding::block(1);
/// ```
///
#[doc = concat!(
    "[custom-field example]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/examples/custom_field/README.md\n",
    "[ownership reference]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/ownership.md\n",
    "[format 1 rules]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#format-1",
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Padding(Policy);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
enum Policy {
    #[default]
    None,
    Block(usize),
    Length(usize),
}

impl Padding {
    /// Stores encoded plaintext at its exact length.
    pub const NONE: Self = Self(Policy::None);

    /// Pads to the next multiple of `size` bytes, always adding at least one byte.
    ///
    /// # Panics
    ///
    /// Panics when `size` is less than 2. In a constant such as
    /// [`Field::PADDING`](crate::Field::PADDING), that is a compile-time error.
    #[must_use]
    pub const fn block(size: usize) -> Self {
        assert!(size >= 2, "padding block size must be at least 2");

        Self(Policy::Block(size))
    }

    /// Pads every encoded value to exactly `len` bytes.
    ///
    /// Encoding a value of `len` bytes or more fails with
    /// [`Error::PaddingOverflow`].
    ///
    /// # Panics
    ///
    /// Panics when `len` is 0. In a constant such as
    /// [`Field::PADDING`](crate::Field::PADDING), that is a compile-time error.
    #[must_use]
    pub const fn length(len: usize) -> Self {
        assert!(len >= 1, "fixed padding length must be at least 1");

        Self(Policy::Length(len))
    }

    /// Reports whether this policy pads plaintext.
    pub(crate) const fn is_padded(self) -> bool {
        !matches!(self.0, Policy::None)
    }

    /// Applies this policy to encoded plaintext.
    ///
    /// Returns `None` when the policy stores plaintext unchanged, so the caller
    /// can encrypt its own buffer without a copy.
    pub(crate) fn pad(self, plaintext: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match self.0 {
            Policy::None => Ok(None),
            Policy::Block(size) => {
                let length_with_marker = plaintext
                    .len()
                    .checked_add(1)
                    .ok_or(Error::MessageTooLong)?;
                let blocks = length_with_marker.div_ceil(size);
                let target = blocks.checked_mul(size).ok_or(Error::MessageTooLong)?;

                Ok(Some(pad_to_length(plaintext, target)))
            }
            Policy::Length(length) => {
                if plaintext.len() >= length {
                    return Err(Error::PaddingOverflow);
                }

                Ok(Some(pad_to_length(plaintext, length)))
            }
        }
    }

    /// Removes padding as this policy would have written it.
    ///
    /// Only format 1 ciphertext, which does not record padding, is read this way.
    pub(crate) fn unpad(self, plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.is_padded() {
            unpad(plaintext)
        } else {
            Ok(plaintext)
        }
    }
}

fn pad_to_length(plaintext: &[u8], target: usize) -> Zeroizing<Vec<u8>> {
    // Preallocate before copying so growth cannot abandon a plaintext-bearing allocation.
    // See ../docs/wire-format.md#key-and-buffer-lifetime.
    let mut padded = Zeroizing::new(Vec::with_capacity(target));
    padded.extend_from_slice(plaintext);
    padded.push(0x80);
    padded.resize(target, 0);

    padded
}

/// Removes ISO/IEC 7816-4 padding from decrypted plaintext.
pub(crate) fn unpad(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let marker = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .filter(|index| plaintext[*index] == 0x80)
        .ok_or(Error::InvalidPadding)?;
    plaintext.truncate(marker);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::Padding;
    use crate::Error;

    #[test]
    fn no_padding_preserves_plaintext() {
        let plaintext = Zeroizing::new(b"exact bytes".to_vec());
        assert_eq!(Padding::NONE.pad(&plaintext).unwrap(), None);
        assert_eq!(
            Padding::NONE.unpad(plaintext).unwrap().as_slice(),
            b"exact bytes"
        );
    }

    #[test]
    fn no_padding_is_the_default() {
        assert_eq!(Padding::default(), Padding::NONE);
    }

    #[test]
    fn block_padding_matches_iso_7816_4_bytes() {
        let padded = Padding::block(8).pad(b"abc").unwrap().unwrap();

        assert_eq!(padded.as_slice(), b"abc\x80\0\0\0\0");
    }

    #[test]
    fn fixed_length_padding_matches_iso_7816_4_bytes() {
        let padded = Padding::length(6).pad(b"abc").unwrap().unwrap();

        assert_eq!(padded.as_slice(), b"abc\x80\0\0");
    }

    #[test]
    fn block_padding_always_adds_a_marker_and_round_trips() {
        for length in 0..=33 {
            let plaintext = vec![b'x'; length];
            let padded = Padding::block(16).pad(&plaintext).unwrap().unwrap();

            assert_eq!(padded.len(), (length / 16 + 1) * 16);
            assert_eq!(
                Padding::block(16).unpad(padded).unwrap().as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn fixed_length_padding_fills_the_target_and_rejects_overflow() {
        for length in 0..32 {
            let plaintext = vec![b'x'; length];
            let padded = Padding::length(32).pad(&plaintext).unwrap().unwrap();

            assert_eq!(padded.len(), 32);
            assert_eq!(
                Padding::length(32).unpad(padded).unwrap().as_slice(),
                plaintext
            );
        }

        assert_eq!(
            Padding::length(32).pad(&[b'x'; 32]),
            Err(Error::PaddingOverflow)
        );
    }

    #[test]
    fn padded_plaintext_can_be_unpadded_with_different_parameters() {
        let padded = Padding::block(16).pad(b"portable").unwrap().unwrap();

        assert_eq!(
            Padding::block(64).unpad(padded.clone()).unwrap().as_slice(),
            b"portable"
        );
        assert_eq!(
            Padding::length(256).unpad(padded).unwrap().as_slice(),
            b"portable"
        );
    }

    #[test]
    fn malformed_padding_is_rejected() {
        for plaintext in [Vec::new(), vec![0; 16], b"missing marker".to_vec()] {
            assert_eq!(
                Padding::block(16).unpad(Zeroizing::new(plaintext)),
                Err(Error::InvalidPadding)
            );
        }
    }

    #[test]
    #[should_panic(expected = "padding block size must be at least 2")]
    fn block_size_below_two_is_rejected() {
        let _ = Padding::block(std::hint::black_box(1));
    }

    #[test]
    #[should_panic(expected = "fixed padding length must be at least 1")]
    fn zero_fixed_length_is_rejected() {
        let _ = Padding::length(std::hint::black_box(0));
    }
}
