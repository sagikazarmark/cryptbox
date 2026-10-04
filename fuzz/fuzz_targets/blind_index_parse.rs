//! Parses arbitrary bytes as a stored blind index, as a reader does with bytes
//! from the database.
//!
//! Parsing must report only `InvalidBlindIndex`, or `UnsupportedBlindIndexVersion`
//! for a header of another version, accept exactly the canonical layout of
//! docs/wire-format.md#stored-layout, and agree between the inspection API and
//! the typed wrapper of each precision.

#![no_main]

use cryptbox::{BlindIndex, BlindIndexSpec, Error, envelope};
use cryptbox_fuzz::{
    Bits1, Bits13, Bits32, Bits256, assert_index_parse_error, blind_index_keys, is_canonical,
};
use libfuzzer_sys::fuzz_target;

// The version byte, the index key ID, and the bit count.
const HEADER_LEN: usize = 19;

fuzz_target!(|bytes: &[u8]| {
    let inspected = envelope::inspect_blind_index(bytes);

    typed::<Bits1>(bytes, &inspected);
    typed::<Bits13>(bytes, &inspected);
    typed::<Bits32>(bytes, &inspected);
    typed::<Bits256>(bytes, &inspected);

    let info = match inspected {
        Ok(info) => info,
        Err(error) => {
            assert_index_parse_error(bytes, &error);
            return;
        }
    };

    let bits = usize::from(info.bits());
    assert_eq!(info.format_version(), 2);
    assert_eq!(bytes[0], 2);
    assert!((1..=256).contains(&bits), "accepted {bits} bits");
    assert_eq!(bytes[17..19], info.bits().to_be_bytes());
    assert_eq!(bytes.len(), HEADER_LEN + bits.div_ceil(8));
    assert_eq!(info.index_key_id().as_bytes(), &bytes[1..17]);

    assert!(
        is_canonical(bytes, info.bits()),
        "accepted nonzero unused bits"
    );
});

fn typed<Spec: BlindIndexSpec<Seal = cryptbox_fuzz::Unpadded>>(
    bytes: &[u8],
    inspected: &Result<envelope::BlindIndexInfo, Error>,
) {
    let parsed = BlindIndex::<Spec>::from_bytes(bytes);

    match inspected {
        Ok(info) if info.bits() == Spec::BITS => {
            let index = parsed.expect("inspection accepted the bytes at this precision");
            assert_eq!(index.as_bytes(), bytes);

            // The check resolves the key generation the untrusted bytes name,
            // which the keyring may not hold. Low precisions match by chance,
            // so the result itself is not asserted.
            match index.is_consistent_with(&b"not derived".to_vec(), &blind_index_keys()) {
                Ok(_) | Err(Error::UnknownBlindIndexKey(_)) => {}
                Err(error) => panic!("unexpected consistency error: {error:?}"),
            }
        }
        Ok(_) => assert_eq!(parsed.err(), Some(Error::InvalidBlindIndex)),
        Err(error) => assert_eq!(parsed.err().as_ref(), Some(error)),
    }
}
