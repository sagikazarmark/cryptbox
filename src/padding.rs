use zeroize::Zeroizing;

use crate::Error;

/// Expands encoded plaintext before encryption to hide its exact length.
///
/// Whether a profile uses padding is persistent schema: enabling or disabling
/// padding for stored ciphertext requires an explicit migration. Padding
/// parameters may change without migration because removal does not depend on
/// the parameter that produced the padding.
pub trait Padding: private::Sealed + Sized + 'static {
    /// Applies this policy to encoded plaintext.
    #[doc(hidden)]
    fn pad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error>;

    /// Removes ISO/IEC 7816-4 padding from decrypted plaintext.
    #[doc(hidden)]
    fn unpad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// Stores encoded plaintext at its exact length.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPadding;

impl private::Sealed for NoPadding {}

impl Padding for NoPadding {
    fn pad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(plaintext)
    }

    fn unpad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(plaintext)
    }
}

/// Pads to the next multiple of `N` bytes, always adding at least one byte.
#[derive(Clone, Copy, Debug, Default)]
pub struct PadToBlock<const N: usize>;

impl<const N: usize> private::Sealed for PadToBlock<N> {}

impl<const N: usize> Padding for PadToBlock<N> {
    fn pad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        const { assert!(N >= 2, "padding block size must be at least 2") };

        let length_with_marker = plaintext
            .len()
            .checked_add(1)
            .ok_or(Error::MessageTooLong)?;
        let blocks = length_with_marker.div_ceil(N);
        let target = blocks.checked_mul(N).ok_or(Error::MessageTooLong)?;
        Ok(pad_to_length(&plaintext, target))
    }

    fn unpad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        const { assert!(N >= 2, "padding block size must be at least 2") };

        unpad(plaintext)
    }
}

/// Pads every encoded value to exactly `N` bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct PadToLength<const N: usize>;

impl<const N: usize> private::Sealed for PadToLength<N> {}

impl<const N: usize> Padding for PadToLength<N> {
    fn pad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        const { assert!(N >= 1, "fixed padding length must be at least 1") };

        if plaintext.len() >= N {
            return Err(Error::PaddingOverflow);
        }

        Ok(pad_to_length(&plaintext, N))
    }

    fn unpad(plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
        const { assert!(N >= 1, "fixed padding length must be at least 1") };

        unpad(plaintext)
    }
}

fn pad_to_length(plaintext: &Zeroizing<Vec<u8>>, target: usize) -> Zeroizing<Vec<u8>> {
    let mut padded = Zeroizing::new(Vec::with_capacity(target));
    padded.extend_from_slice(plaintext);
    padded.push(0x80);
    padded.resize(target, 0);

    padded
}

fn unpad(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let marker = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .filter(|index| plaintext[*index] == 0x80)
        .ok_or(Error::InvalidPadding)?;
    plaintext.truncate(marker);

    Ok(plaintext)
}

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{NoPadding, PadToBlock, PadToLength, Padding};
    use crate::Error;

    #[test]
    fn no_padding_preserves_plaintext() {
        let plaintext = Zeroizing::new(b"exact bytes".to_vec());
        let padded = NoPadding::pad(plaintext).unwrap();

        assert_eq!(padded.as_slice(), b"exact bytes");
        assert_eq!(NoPadding::unpad(padded).unwrap().as_slice(), b"exact bytes");
    }

    #[test]
    fn block_padding_always_adds_a_marker_and_round_trips() {
        for length in 0..=33 {
            let plaintext = vec![b'x'; length];
            let padded = PadToBlock::<16>::pad(Zeroizing::new(plaintext.clone())).unwrap();

            assert_eq!(padded.len(), (length / 16 + 1) * 16);
            assert_eq!(
                PadToBlock::<16>::unpad(padded).unwrap().as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn fixed_length_padding_fills_the_target_and_rejects_overflow() {
        for length in 0..32 {
            let plaintext = vec![b'x'; length];
            let padded = PadToLength::<32>::pad(Zeroizing::new(plaintext.clone())).unwrap();

            assert_eq!(padded.len(), 32);
            assert_eq!(
                PadToLength::<32>::unpad(padded).unwrap().as_slice(),
                plaintext
            );
        }

        assert_eq!(
            PadToLength::<32>::pad(Zeroizing::new(vec![b'x'; 32])),
            Err(Error::PaddingOverflow)
        );
    }

    #[test]
    fn padded_plaintext_can_be_unpadded_with_different_parameters() {
        let padded = PadToBlock::<16>::pad(Zeroizing::new(b"portable".to_vec())).unwrap();

        assert_eq!(
            PadToBlock::<64>::unpad(padded.clone()).unwrap().as_slice(),
            b"portable"
        );
        assert_eq!(
            PadToLength::<256>::unpad(padded).unwrap().as_slice(),
            b"portable"
        );
    }

    #[test]
    fn malformed_padding_is_rejected() {
        for plaintext in [Vec::new(), vec![0; 16], b"missing marker".to_vec()] {
            assert_eq!(
                PadToBlock::<16>::unpad(Zeroizing::new(plaintext)),
                Err(Error::InvalidPadding)
            );
        }
    }
}
