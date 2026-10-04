//! Seals arbitrary plaintext, standalone or as a record's field, then mutates
//! the envelope as the fuzzer chooses.
//!
//! The unmodified envelope must open to the plaintext. Every byte of a mutated
//! envelope is authenticated, so it must never open, whatever plaintext it
//! would yield, and must fail with a structural or authentication error, never
//! one only authenticated plaintext can cause.

#![no_main]

use arbitrary::Arbitrary;
use cryptbox::{Error, InRecord, Seal, Sealed};
use cryptbox_fuzz::{Padded, Unpadded, assert_forgery_error, assert_parse_error, encryption_keys};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    plaintext: Vec<u8>,
    padded: bool,
    context: Context,
    mutation: Mutation,
}

/// What the value is sealed under besides its seal.
#[derive(Arbitrary, Debug)]
enum Context {
    Standalone,
    Record(i64),
    UuidRecord([u8; 16]),
}

/// One change to the stored envelope.
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
    /// Applies the mutation to `envelope`, which is never empty. The result
    /// always differs from it.
    fn apply(&self, envelope: &[u8]) -> Vec<u8> {
        let mut bytes = envelope.to_vec();

        match *self {
            Self::Flip { index, mask } => bytes[index % envelope.len()] ^= mask.max(1),
            Self::Truncate { len } => bytes.truncate(len % envelope.len()),
            Self::Insert { index, byte } => bytes.insert(index % (envelope.len() + 1), byte),
            Self::Remove { index } => {
                bytes.remove(index % envelope.len());
            }
        }

        bytes
    }
}

fuzz_target!(|input: Input| {
    if input.padded {
        round_trip::<Padded>(&input);
    } else {
        round_trip::<Unpadded>(&input);
    }
});

fn round_trip<F: Seal<Value = Vec<u8>>>(input: &Input) {
    let keys = encryption_keys();
    let plaintext = &input.plaintext;

    // Each context seals, then opens bytes as a reader does: parse, then open.
    match &input.context {
        Context::Standalone => {
            let sealed = Sealed::<F>::seal(plaintext, &keys).expect("sealing succeeds");

            // Another context kind is named by the fingerprint before any key.
            let other = Sealed::<F, InRecord<i64>>::from_bytes(sealed.as_bytes()).unwrap();
            assert_eq!(other.open_in(&0, &keys), Err(Error::ContextMismatch));
            // Another seal of the same context kind fails authentication.
            let other = Sealed::<Swapped<F>>::from_bytes(sealed.as_bytes()).unwrap();
            assert_eq!(other.open(&keys), Err(Error::AuthenticationFailed));

            check(plaintext, sealed.as_bytes(), &input.mutation, |bytes| {
                Sealed::<F>::from_bytes(bytes).map(|sealed| sealed.open(&keys))
            });
        }
        Context::Record(id) => {
            let sealed = Sealed::<F, InRecord<i64>>::seal_in(plaintext, id, &keys)
                .expect("sealing succeeds");

            // Another row fails authentication; another kind of record ID or a
            // standalone reader is named by the fingerprint.
            assert_eq!(
                sealed.open_in(&id.wrapping_add(1), &keys),
                Err(Error::AuthenticationFailed)
            );
            let other = Sealed::<F, InRecord<[u8; 16]>>::from_bytes(sealed.as_bytes()).unwrap();
            let mut uuid = [0; 16];
            uuid[8..].copy_from_slice(&id.to_be_bytes());
            assert_eq!(other.open_in(&uuid, &keys), Err(Error::ContextMismatch));
            let other = Sealed::<F>::from_bytes(sealed.as_bytes()).unwrap();
            assert_eq!(other.open(&keys), Err(Error::ContextMismatch));

            check(plaintext, sealed.as_bytes(), &input.mutation, |bytes| {
                Sealed::<F, InRecord<i64>>::from_bytes(bytes)
                    .map(|sealed| sealed.open_in(id, &keys))
            });
        }
        Context::UuidRecord(id) => {
            let sealed = Sealed::<F, InRecord<[u8; 16]>>::seal_in(plaintext, id, &keys)
                .expect("sealing succeeds");

            let mut other_id = *id;
            other_id[15] ^= 1;
            assert_eq!(
                sealed.open_in(&other_id, &keys),
                Err(Error::AuthenticationFailed)
            );

            check(plaintext, sealed.as_bytes(), &input.mutation, |bytes| {
                Sealed::<F, InRecord<[u8; 16]>>::from_bytes(bytes)
                    .map(|sealed| sealed.open_in(id, &keys))
            });
        }
    }
}

/// Opens the unmodified envelope, then a mutation of it, with `open`: the outer
/// result is parsing, the inner opening.
fn check(
    plaintext: &[u8],
    envelope: &[u8],
    mutation: &Mutation,
    open: impl Fn(Vec<u8>) -> Result<Result<Vec<u8>, Error>, Error>,
) {
    assert_eq!(
        open(envelope.to_vec()),
        Ok(Ok(plaintext.to_vec())),
        "the unmodified envelope must open"
    );

    let mutated = mutation.apply(envelope);
    assert_ne!(mutated, envelope);

    match open(mutated) {
        Err(error) => assert_parse_error(&error),
        Ok(Err(error)) => assert_forgery_error(&error),
        Ok(Ok(opened)) => panic!(
            "a mutated envelope opened ({mutation:?}); same plaintext: {}",
            opened == plaintext
        ),
    }
}

/// The seal `F` under another seal ID.
struct Swapped<F>(std::marker::PhantomData<F>);

impl<F: Seal<Value = Vec<u8>>> Seal for Swapped<F> {
    const ID: cryptbox::SealId = cryptbox::seal_id!("fedcba98-7654-4321-8fed-cba987654321");
    const PADDING: cryptbox::Padding = F::PADDING;
    type Value = Vec<u8>;
    type Codec = F::Codec;
}
