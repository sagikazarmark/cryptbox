//! Derives a blind index from arbitrary normalized bytes, then mutates it as
//! the fuzzer chooses.
//!
//! A derived index must re-parse, name the current key generation, be one of
//! the probes for the same input, and be consistent with its value. A mutated
//! index must be rejected, or parse as canonical bytes that are not consistent
//! with the value.

#![no_main]

use arbitrary::Arbitrary;
use cryptbox::{BlindIndex, BlindIndexSpec, Error, envelope};
use cryptbox_fuzz::{Bits1, Bits13, Bits32, Bits256, Unpadded, blind_index_keys, is_canonical};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    value: Vec<u8>,
    precision: Precision,
    mutation: Mutation,
}

#[derive(Arbitrary, Debug)]
enum Precision {
    Bits1,
    Bits13,
    Bits32,
    Bits256,
}

/// One change to the stored index.
#[derive(Arbitrary, Debug)]
enum Mutation {
    /// XOR one byte with a nonzero mask.
    Flip { index: usize, mask: u8 },
    /// Keep a strict prefix.
    Truncate { len: usize },
    /// Insert one byte.
    Insert { index: usize, byte: u8 },
    /// Remove one byte.
    Remove { index: usize },
}

impl Mutation {
    /// Applies the mutation to `stored`, which is never empty. The result
    /// always differs from it.
    fn apply(&self, stored: &[u8]) -> Vec<u8> {
        let mut bytes = stored.to_vec();

        match *self {
            Self::Flip { index, mask } => bytes[index % stored.len()] ^= mask.max(1),
            Self::Truncate { len } => bytes.truncate(len % stored.len()),
            Self::Insert { index, byte } => bytes.insert(index % (stored.len() + 1), byte),
            Self::Remove { index } => {
                bytes.remove(index % stored.len());
            }
        }

        bytes
    }
}

fuzz_target!(|input: Input| {
    match input.precision {
        Precision::Bits1 => round_trip::<Bits1>(&input),
        Precision::Bits13 => round_trip::<Bits13>(&input),
        Precision::Bits32 => round_trip::<Bits32>(&input),
        Precision::Bits256 => round_trip::<Bits256>(&input),
    }
});

fn round_trip<Spec: BlindIndexSpec<Seal = Unpadded, Query = [u8]>>(input: &Input) {
    let keys = blind_index_keys();
    let value = &input.value;

    let derived = BlindIndex::<Spec>::derive(value, &keys).expect("derivation succeeds");
    let stored = derived.as_bytes();

    let info = envelope::inspect_blind_index(stored).expect("a derived index parses");
    assert_eq!(info.bits(), Spec::BITS);
    assert_eq!(info.index_key_id(), keys.current().id());
    assert_eq!(
        BlindIndex::<Spec>::from_bytes(stored).as_ref(),
        Ok(&derived),
        "a derived index re-parses to itself"
    );
    assert_eq!(derived.is_consistent_with(value, &keys), Ok(true));

    // Derivation is deterministic, and a probe for the same input finds it.
    assert_eq!(
        BlindIndex::<Spec>::derive(value, &keys).as_ref(),
        Ok(&derived)
    );
    let probes = BlindIndex::<Spec>::probes(value, &keys).expect("probing succeeds");
    assert_eq!(probes.len(), 2, "one probe per readable generation");
    assert!(probes.contains(&derived));

    let mutated = input.mutation.apply(stored);
    assert_ne!(mutated, stored);

    match BlindIndex::<Spec>::from_bytes(mutated.clone()) {
        Err(error) => assert_eq!(error, Error::InvalidBlindIndex),
        Ok(index) => {
            // Accepted bytes are canonical: they are the stored bytes as given,
            // with the unused low bits of the final byte zero.
            assert_eq!(index.as_bytes(), mutated);
            assert!(is_canonical(&mutated, Spec::BITS));

            // Only the key ID or the digest can change and still parse, and a
            // stored index is consistent only when it equals the derived one.
            match index.is_consistent_with(value, &keys) {
                Ok(false) | Err(Error::UnknownBlindIndexKey(_)) => {}
                other => panic!(
                    "mutated index {mutation:?} checked as {other:?}",
                    mutation = input.mutation
                ),
            }
        }
    }
}
