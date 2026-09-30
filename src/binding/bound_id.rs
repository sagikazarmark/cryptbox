use super::{PartId, PartSpec, PartType, TenantId, presets::TENANT_PART};

/// An application ID type whose values a seal's values are bound to, such as
/// an org or a workspace ID.
///
/// [`KIND_ID`](Self::KIND_ID) names the kind of value once, on the type: every
/// value bound to an `OrgId` is bound under the same part ID, whichever seal or
/// record binds it. With [`PartType::KIND`], it is persistent schema: changing
/// either is a migration. See the [wire format].
///
/// With the `derive` feature, `#[derive(BoundId)]` implements it and
/// [`PartType`] for a newtype over a part type, taking the kind of value from
/// `#[cryptbox(kind = "…")]`, a fresh UUID:
///
/// ```
/// # #[cfg(feature = "derive")] {
/// use cryptbox::BoundId;
///
/// #[derive(BoundId, Clone, Copy, PartialEq)]
/// #[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
/// struct OrgId([u8; 16]);
///
/// assert_eq!(OrgId::KIND_ID, cryptbox::part_id!("59881c28-3003-4047-847f-d7cc73b140e5"));
/// # }
/// ```
///
/// [`TenantId`] is a bound ID of the `Tenant` preset's kind.
///
#[doc = concat!(
    "[wire format]: ", env!("CARGO_PKG_REPOSITORY"), "/blob/main/docs/wire-format.md#binding",
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a bound ID type",
    label = "a bound value needs a type that implements `BoundId`",
    note = "wrap the ID in a newtype, such as `struct OrgId(Uuid);`, and add \
            `#[derive(BoundId)]` and `#[cryptbox(kind = \"<uuid>\")]` to it"
)]
pub trait BoundId: PartType + Send + Sync + 'static {
    /// The stable ID of this kind of bound value, its part ID.
    const KIND_ID: PartId;

    /// The part this type binds as: its kind ID and value kind.
    const PART: PartSpec = PartSpec::new(Self::KIND_ID, Self::KIND);
}

impl BoundId for TenantId {
    const KIND_ID: PartId = TENANT_PART.id();
}

/// The bound ID types a seal binds its values to: `()`, or a tuple of up to
/// four [`BoundId`] types of distinct kinds, such as `(OrgId, WorkspaceId)`.
///
/// The order is the order in which callers pass values; the binding sorts its
/// parts, so reordering the types does not change stored bytes. Two types of
/// the same kind fail the build when the list is first used:
///
/// ```compile_fail,E0080
/// use cryptbox::{BoundList, TenantId};
///
/// let _ = <(TenantId, TenantId)>::PARTS;
/// ```
///
/// This trait is sealed: `()` and the tuples are its only implementations.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a list of bound ID types",
    label = "use `()`, or a tuple of up to four `BoundId` types",
    note = "a one-type list is a one-tuple: `(OrgId,)`"
)]
pub trait BoundList: sealed::Sealed + 'static {
    /// One part per type, in list order.
    const PARTS: &'static [PartSpec];
}

mod sealed {
    pub trait Sealed {}
}

// Panics become build errors in `const` context.
const fn check_bound_parts(parts: &[PartSpec]) {
    let mut index = 0;
    while index < parts.len() {
        let id = u128::from_be_bytes(parts[index].id);
        assert!(id != 0, "a bound ID's kind ID must not be nil");
        let mut other = index + 1;
        while other < parts.len() {
            assert!(
                u128::from_be_bytes(parts[other].id) != id,
                "a seal binds each kind of bound value at most once"
            );
            other += 1;
        }
        index += 1;
    }
}

impl sealed::Sealed for () {}

impl BoundList for () {
    const PARTS: &'static [PartSpec] = &[];
}

macro_rules! bound_list {
    ($($ty:ident),+) => {
        impl<$($ty: BoundId),+> sealed::Sealed for ($($ty,)+) {}

        impl<$($ty: BoundId),+> BoundList for ($($ty,)+) {
            const PARTS: &'static [PartSpec] = {
                let parts = &[$($ty::PART),+];
                check_bound_parts(parts);
                parts
            };
        }
    };
}

bound_list!(A);
bound_list!(A, B);
bound_list!(A, B, C);
bound_list!(A, B, C, D);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingDomain, PartKind, PartValue, Scope, Tenant, binding::BindingDeclaration, part_id,
        seal_id,
    };

    const SEAL: [u8; 16] = *seal_id!("12345678-1234-4234-8234-1234567890ab").as_bytes();

    struct OrgId([u8; 16]);

    impl PartType for OrgId {
        const KIND: PartKind = PartKind::Uuid;

        fn part_value(&self) -> PartValue<'_> {
            PartValue::Uuid(self.0)
        }

        fn from_part_value(value: PartValue<'_>) -> Result<Self, crate::Error> {
            <[u8; 16]>::from_part_value(value).map(Self)
        }
    }

    impl BoundId for OrgId {
        const KIND_ID: PartId = part_id!("11111111-1111-1111-1111-111111111111");
    }

    fn domain<L: BoundList>(values: &[PartValue<'_>]) -> BindingDomain {
        BindingDomain::scoped(&SEAL, BindingDeclaration::new(L::PARTS, None), values, None).unwrap()
    }

    #[test]
    fn a_tenant_id_binds_as_the_tenant_preset() {
        let tenant = TenantId::new("acme").unwrap();
        let scoped = BindingDomain::of::<Tenant>(&SEAL, &Tenant(tenant.clone()), None).unwrap();
        let bound = domain::<(TenantId,)>(&[tenant.part_value()]);

        assert_eq!(bound.as_bytes(), scoped.as_bytes());
        assert_eq!(bound.fingerprint(), scoped.fingerprint());
        assert_eq!(<(TenantId,)>::PARTS, Tenant::PARTS);
    }

    #[test]
    fn list_order_does_not_change_the_binding() {
        let (org, tenant) = (OrgId([0x33; 16]), TenantId::new("acme").unwrap());
        let forward = domain::<(OrgId, TenantId)>(&[org.part_value(), tenant.part_value()]);
        let backward = domain::<(TenantId, OrgId)>(&[tenant.part_value(), org.part_value()]);

        assert_eq!(forward.as_bytes(), backward.as_bytes());
        assert_eq!(forward.fingerprint(), backward.fingerprint());
    }

    #[test]
    #[should_panic(expected = "at most once")]
    fn a_kind_repeated_in_a_list_fails() {
        check_bound_parts(&[OrgId::PART, OrgId::PART]);
    }
}
