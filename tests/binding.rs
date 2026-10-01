//! Public-boundary tests for record ID types.

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, Padding, PartKind, PartType, PartValue, Raw, Seal,
    SealId, Sealed, seal_id,
};

/// A record ID whose values are not of the kind it declares.
struct Mismatched;

impl PartType for Mismatched {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(1)
    }
}

struct MismatchedNote;

impl Seal for MismatchedNote {
    const ID: SealId = seal_id!("2ad30df3-8b86-47cf-9115-b0c78c14aae1");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Record = Mismatched;
    type Indexes = ();
}

#[test]
fn a_record_id_of_another_kind_than_its_type_declares_is_rejected() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();

    assert_eq!(
        Sealed::<MismatchedNote>::seal(&b"note".to_vec(), &Mismatched, &keys),
        Err(Error::InvalidBinding)
    );
}
