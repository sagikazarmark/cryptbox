//! Public-boundary tests for record ID types.

use cryptbox::{
    EncryptionKey, EncryptionKeyring, Error, Padding, Raw, RecordId, RecordIdType, Seal, SealId,
    Sealed, seal_id,
};

/// A row's ID, an application-owned newtype bound as the UUID it wraps.
struct RowId([u8; 16]);

impl RecordIdType for RowId {
    type Repr = [u8; 16];

    fn repr(&self) -> &[u8; 16] {
        &self.0
    }
}

macro_rules! note {
    ($name:ident, $record:ty) => {
        struct $name;

        impl Seal for $name {
            const ID: SealId = seal_id!("2ad30df3-8b86-47cf-9115-b0c78c14aae1");
            const PADDING: Padding = Padding::NONE;
            type Value = Vec<u8>;
            type Codec = Raw;
            type Record = $record;
            type Indexes = ();
        }
    };
}

note!(RowNote, RowId);
note!(UuidNote, [u8; 16]);
note!(NumberNote, i64);

fn keys() -> EncryptionKeyring {
    EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap()
}

#[test]
fn a_newtype_binds_as_the_type_it_wraps() {
    let keys = keys();
    let sealed = Sealed::<RowNote>::seal(&b"note".to_vec(), &RowId([7; 16]), &keys).unwrap();

    let as_uuid = Sealed::<UuidNote>::from_bytes(sealed.into_bytes()).unwrap();
    assert_eq!(as_uuid.open(&[7; 16], &keys).unwrap(), b"note");
    assert_eq!(RecordId::of(&RowId([7; 16])), RecordId::Uuid([7; 16]));
}

#[test]
fn a_record_id_of_another_kind_is_another_declaration() {
    let keys = keys();
    let sealed = Sealed::<NumberNote>::seal(&b"note".to_vec(), &7, &keys).unwrap();

    let as_uuid = Sealed::<UuidNote>::from_bytes(sealed.into_bytes()).unwrap();
    assert_eq!(
        as_uuid.open(&[7; 16], &keys).unwrap_err(),
        Error::BindingMismatch
    );
}
