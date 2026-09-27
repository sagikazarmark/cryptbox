use std::fmt;

use super::{Binding, PartKind, PartSpec, PartValue, PartValues};
use crate::Error;

/// A binding with no parts: values are bound to their field ID only.
///
/// Its encoding is byte-identical to the field-only binding of earlier releases
/// (tag `01`), unless the field also binds a record. Blind indexes take no
/// arguments, and every value shares one [`KeyScope`](crate::KeyScope).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct FieldOnly;

impl Binding for FieldOnly {
    const PARTS: &'static [PartSpec] = &[];
    type IndexArgs = ();

    fn values(&self) -> PartValues<'_> {
        PartValues::new()
    }

    fn index_values((): &()) -> PartValues<'_> {
        PartValues::new()
    }
}

/// A binding with a single tenant part, which scopes keys and blind indexes.
///
/// The tenant is the [shred unit](Binding#shredding) when each tenant's root
/// keys are stored independently. Blind-index queries take the tenant itself as
/// their arguments. Its one part is persistent schema: part ID
/// `1e8306bf-3135-4570-831c-6732f92550e9`, kind bytes, role `keys`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Tenant(pub TenantId);

// Persistent schema: never change it. See ../../docs/wire-format.md#presets.
const TENANT_PART: PartSpec = PartSpec::keys(
    crate::part_id!("1e8306bf-3135-4570-831c-6732f92550e9"),
    PartKind::Bytes,
);

impl Binding for Tenant {
    const PARTS: &'static [PartSpec] = &[TENANT_PART];
    type IndexArgs = Self;

    fn values(&self) -> PartValues<'_> {
        Self::index_values(self)
    }

    fn index_values(args: &Self) -> PartValues<'_> {
        PartValues::from([PartValue::Bytes(args.0.as_bytes())])
    }
}

/// An opaque, non-empty tenant identifier.
///
/// The bytes are bound as given. A UUID tenant is its 16 bytes, so
/// [`TenantId::from_uuid`] and [`TenantId::new`] over the same bytes name the
/// same tenant.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TenantId(Box<[u8]>);

impl TenantId {
    /// Creates a tenant ID from opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when `bytes` is empty.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::InvalidBinding);
        }

        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Creates a tenant ID from a UUID's 16 bytes.
    #[must_use]
    pub fn from_uuid(uuid: [u8; 16]) -> Self {
        Self(Box::new(uuid))
    }

    /// Returns the tenant ID's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantId")
            .field(&format_args!("{}", hex::encode(&self.0)))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindingDomain, FieldId, RecordId, ShapeFingerprint, field_id};

    const FIELD: FieldId = field_id!("12345678-1234-4234-8234-1234567890ab");

    #[test]
    fn field_only_is_byte_identical_to_field_binding() {
        let domain = BindingDomain::of(FIELD, &FieldOnly, None).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "01123456781234423482341234567890ab"
        );
        assert_eq!(domain.fingerprint(), None);
    }

    #[test]
    fn field_only_with_a_record_binds_the_record_alone() {
        let domain = BindingDomain::of(FIELD, &FieldOnly, Some(RecordId::from(1_i64))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "02123456781234423482341234567890ab020000000800000000000000010000"
        );
    }

    #[test]
    fn tenant_binds_one_bytes_keys_part() {
        let tenant = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
        let domain = BindingDomain::of(FIELD, &tenant, None).unwrap();

        // docs/wire-format.md#presets
        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "02",
                "123456781234423482341234567890ab",
                "00",
                "0001",
                "1e8306bf31354570831c6732f92550e9",
                "03",
                "00000004",
                "61636d65",
            )
        );
        assert_eq!(
            domain.fingerprint(),
            Some(ShapeFingerprint::from_bytes(hex_array("f8311e0a178867bc")))
        );
    }

    #[test]
    fn a_uuid_tenant_is_its_sixteen_bytes() {
        assert_eq!(
            TenantId::from_uuid([0x42; 16]),
            TenantId::new([0x42; 16].to_vec()).unwrap()
        );
    }

    #[test]
    fn a_tenant_id_is_never_empty() {
        assert_eq!(TenantId::new(Vec::new()), Err(Error::InvalidBinding));
    }

    fn hex_array(value: &str) -> [u8; 8] {
        hex::decode(value).unwrap().try_into().unwrap()
    }
}
