//! Public-boundary tests for bound values and part types.

use cryptbox::{
    BoundId, EncryptionKey, EncryptionKeyring, Error, Padding, PartId, PartKind, PartType,
    PartValue, Raw, Seal, SealId, Sealed, TenantId, part_id, seal_id,
};

/// A bound ID whose values are not of the kind it declares.
struct Mismatched;

impl PartType for Mismatched {
    const KIND: PartKind = PartKind::Uuid;

    fn part_value(&self) -> PartValue<'_> {
        PartValue::I64(1)
    }

    fn from_part_value(_: PartValue<'_>) -> Result<Self, Error> {
        Err(Error::InvalidBinding)
    }
}

impl BoundId for Mismatched {
    const KIND_ID: PartId = part_id!("2b0e5f1a-7c3d-4e98-b6a2-0f4d8c1e9a37");
}

struct MismatchedNote;

impl Seal for MismatchedNote {
    const ID: SealId = seal_id!("2ad30df3-8b86-47cf-9115-b0c78c14aae1");
    const PADDING: Padding = Padding::NONE;
    type Value = Vec<u8>;
    type Codec = Raw;
    type Bound = (Mismatched,);
    type Record = ();
    type Indexes = ();
}

#[test]
fn a_value_of_another_kind_than_its_part_is_rejected() {
    let keys = EncryptionKeyring::new(EncryptionKey::generate().unwrap(), []).unwrap();

    assert_eq!(
        Sealed::<MismatchedNote>::seal(&b"note".to_vec(), &Mismatched, &keys),
        Err(Error::InvalidBinding)
    );
}

#[test]
fn part_types_read_back_the_values_they_bind() {
    let uuid = [7; 16];
    let tenant = TenantId::new("acme").unwrap();

    assert_eq!(<[u8; 16]>::from_part_value(uuid.part_value()), Ok(uuid));
    assert_eq!(i64::from_part_value((-9_i64).part_value()), Ok(-9));
    assert_eq!(
        Vec::<u8>::from_part_value(b"acme".to_vec().part_value()),
        Ok(b"acme".to_vec())
    );
    assert_eq!(
        Box::<[u8]>::from_part_value(PartValue::Bytes(b"acme")),
        Ok(Box::from(&b"acme"[..]))
    );
    assert_eq!(TenantId::from_part_value(tenant.part_value()), Ok(tenant));
}

#[test]
fn part_types_reject_values_of_another_kind() {
    assert_eq!(
        <[u8; 16]>::from_part_value(PartValue::I64(1)),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        i64::from_part_value(PartValue::Bytes(b"1")),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Vec::<u8>::from_part_value(PartValue::Uuid([1; 16])),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        TenantId::from_part_value(PartValue::Bytes(b"")),
        Err(Error::InvalidBinding),
        "a tenant ID is never empty"
    );
}
