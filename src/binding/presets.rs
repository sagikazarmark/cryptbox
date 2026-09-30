use std::fmt;

use super::{FromParts, PartKind, PartSpec, PartType, PartValue, PartValues, Scope};
use crate::Error;

// The empty scope: values are bound to their seal ID only. Blind indexes take
// no arguments.
impl Scope for () {
    const PARTS: &'static [PartSpec] = &[];

    fn values(&self) -> PartValues<'_> {
        PartValues::new()
    }
}

impl FromParts for () {
    fn from_parts(values: &[PartValue<'_>]) -> Result<(), Error> {
        match values {
            [] => Ok(()),
            _ => Err(Error::InvalidBinding),
        }
    }
}

/// A scope with a single tenant part.
///
/// A tenant can be [shredded](Scope#shredding) on its own when the application
/// keeps each tenant's root keys separately. A blind index over a tenant-scoped seal takes
/// `Tenant` as its index scope, so its queries pass the tenant. Its one part is persistent schema: part ID
/// `1e8306bf-3135-4570-831c-6732f92550e9`, kind bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Tenant(pub TenantId);

// Persistent schema: never change it. See ../../docs/wire-format.md#presets.
const TENANT_PART: PartSpec = PartSpec::new(
    crate::part_id!("1e8306bf-3135-4570-831c-6732f92550e9"),
    PartKind::Bytes,
);

impl Scope for Tenant {
    const PARTS: &'static [PartSpec] = &[TENANT_PART];

    fn values(&self) -> PartValues<'_> {
        PartValues::from([PartValue::Bytes(self.0.as_bytes())])
    }
}

impl FromParts for Tenant {
    fn from_parts(values: &[PartValue<'_>]) -> Result<Self, Error> {
        match values {
            [tenant] => TenantId::from_part_value(*tenant).map(Self),
            _ => Err(Error::InvalidBinding),
        }
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
    use crate::{BindingDomain, Recorded, seal_id};

    const SEAL: [u8; 16] = *seal_id!("12345678-1234-4234-8234-1234567890ab").as_bytes();

    #[test]
    fn unscoped_is_the_empty_binding() {
        let domain = BindingDomain::of::<()>(&SEAL, &(), None).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            "123456781234423482341234567890ab0000"
        );
        assert_eq!(domain.fingerprint(), hex_array("65640fc8333534b9"));
    }

    #[test]
    fn unscoped_with_a_record_binds_the_record_alone() {
        let domain =
            BindingDomain::of::<Recorded<(), i64>>(&SEAL, &(), Some(PartValue::I64(1))).unwrap();

        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "123456781234423482341234567890ab",
                "0001",
                "00000000000000000000000000000000",
                "02",
                "00000008",
                "0000000000000001",
            )
        );
        assert_eq!(domain.fingerprint(), hex_array("76081b730530f822"));
    }

    #[test]
    fn tenant_binds_one_bytes_part() {
        let tenant = Tenant(TenantId::new(b"acme".to_vec()).unwrap());
        let domain = BindingDomain::of::<Tenant>(&SEAL, &tenant, None).unwrap();

        // docs/wire-format.md#presets
        assert_eq!(
            hex::encode(domain.as_bytes()),
            concat!(
                "123456781234423482341234567890ab",
                "0001",
                "1e8306bf31354570831c6732f92550e9",
                "03",
                "00000004",
                "61636d65",
            )
        );
        assert_eq!(domain.fingerprint(), hex_array("9b5379b1f03beb17"));
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
