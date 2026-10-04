//! Parses arbitrary bytes as a stored envelope, as a reader does with bytes
//! from the database.
//!
//! Parsing must report only structural errors, agree with the layout table in
//! docs/wire-format.md, and agree between the inspection API and the typed
//! wrapper. A parsed envelope must never open: it did not come from a writer.

#![no_main]

use cryptbox::{Error, InRecord, Sealed, envelope};
use cryptbox_fuzz::{Padded, Unpadded, assert_forgery_error, assert_parse_error, encryption_keys};
use libfuzzer_sys::fuzz_target;

// docs/wire-format.md#envelope: the prefix, then at least the tag.
const MIN_ENVELOPE_LEN: usize = 71;
// The magic, then format version 2 and suite 1.
const SUPPORTED_HEADER: &[u8] = b"CBX\0\x02\x01";

fuzz_target!(|bytes: &[u8]| {
    check(bytes);

    // Coverage guidance rarely guesses the magic, so also parse the input after
    // it, and after the supported version and suite, to reach the later checks.
    for prefix in [&SUPPORTED_HEADER[..4], SUPPORTED_HEADER] {
        check(&[prefix, bytes].concat());
    }
});

fn check(bytes: &[u8]) {
    let inspected = envelope::inspect_ciphertext(bytes);
    let typed = Sealed::<Unpadded>::from_bytes(bytes);

    // The typed wrapper accepts exactly what inspection accepts.
    assert_eq!(typed.as_ref().err(), inspected.as_ref().err());

    let info = match inspected {
        Ok(info) => info,
        Err(error) => {
            assert_parse_error(&error);
            assert_eq!(
                error == Error::NotCiphertext,
                !envelope::is_ciphertext(bytes),
                "only a missing magic reports NotCiphertext"
            );
            return;
        }
    };

    assert!(envelope::is_ciphertext(bytes));
    assert!(
        bytes.len() >= MIN_ENVELOPE_LEN,
        "accepted {} bytes",
        bytes.len()
    );
    assert_eq!(info.format_version(), 2);
    assert_eq!(info.format_version(), bytes[4]);
    assert_eq!(info.suite_id(), 1);
    assert_eq!(info.suite_id(), bytes[5]);
    assert_eq!(bytes[6] & !0x01, 0, "a reserved flag bit was accepted");
    assert_eq!(info.padded(), bytes[6] & 0x01 != 0);
    assert_eq!(info.key_id().as_bytes(), &bytes[7..23]);
    assert_eq!(info.context_fingerprint(), bytes[23..31]);

    let sealed = typed.expect("inspection accepted the bytes");
    assert_eq!(sealed.as_bytes(), bytes);
    assert_eq!(sealed.key_id(), info.key_id());

    // Arbitrary bytes are not authentic under any seal or context.
    let keys = encryption_keys();
    assert_forgery_error(&sealed.open(&keys).unwrap_err());
    match sealed.needs_reseal(&keys) {
        Ok(_) | Err(Error::ContextMismatch) => {}
        Err(error) => panic!("unexpected needs_reseal error: {error:?}"),
    }

    let padded = Sealed::<Padded>::from_bytes(bytes).expect("parsing ignores the seal");
    assert_forgery_error(&padded.open(&keys).unwrap_err());

    let record =
        Sealed::<Unpadded, InRecord<i64>>::from_bytes(bytes).expect("parsing ignores the context");
    assert_forgery_error(&record.open_in(&7, &keys).unwrap_err());

    let record = Sealed::<Unpadded, InRecord<Vec<u8>>>::from_bytes(bytes)
        .expect("parsing ignores the context");
    assert_forgery_error(&record.open_in(&b"row".to_vec(), &keys).unwrap_err());
}
