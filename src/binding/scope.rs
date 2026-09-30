use super::{PartRole, PartSpec, PartValue, Scope, check_parts, check_values};
use crate::{Error, PartId};

/// The [`keys`](PartRole::Keys) parts of a binding: the scope that key custody
/// follows.
///
/// Two bindings of the same type share a key scope when their `keys` values
/// are equal, whatever their bound-only values. A binding without
/// `keys` parts, such as the empty scope `()`, has the empty key scope,
/// which every such binding shares. A record never contributes to it.
///
/// A key scope is owned and implements `Hash + Eq`, so an application can use it
/// to cache or look up the keys of each scope. It is the
/// [shred unit](Scope#shredding) when each scope's root keys are stored
/// independently.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyScope(Box<[(PartId, ScopeValue)]>);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ScopeValue {
    Uuid([u8; 16]),
    I64(i64),
    Bytes(Box<[u8]>),
}

impl KeyScope {
    /// Returns the key scope of a binding.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when the binding's values do not match
    /// its parts; see [`Scope`].
    pub fn of<B: Scope>(binding: &B) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let values = binding.values();
        check_values(B::PARTS, &values.0)?;

        Ok(Self::keys_of(B::PARTS.iter().zip(&values.0)))
    }

    /// Returns the key scope of the given `keys` part values of binding `B`, one
    /// per `keys` part in [`PARTS`](Scope::PARTS) order.
    ///
    /// It equals the key scope of every binding of `B` with the same `keys`
    /// values. Use it where only the key scope is known, such as when shredding
    /// one org's data.
    ///
    /// ```
    /// use cryptbox::{KeyScope, PartValue, Tenant, TenantId};
    ///
    /// let acme = Tenant(TenantId::new("acme")?);
    ///
    /// assert_eq!(KeyScope::of_keys::<Tenant>(&[PartValue::Bytes(b"acme")])?, KeyScope::of(&acme)?);
    /// # Ok::<(), cryptbox::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when the values do not match the
    /// binding's `keys` parts: a missing or extra value, a value of the wrong
    /// kind, or an empty value.
    pub fn of_keys<B: Scope>(values: &[PartValue<'_>]) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let specs = B::PARTS.iter().filter(|spec| spec.role == PartRole::Keys);
        check_values(specs.clone(), values)?;

        Ok(Self::keys_of(specs.zip(values)))
    }

    /// The `keys` parts and their values, in `PARTS` order.
    #[cfg(feature = "restate")]
    pub(crate) fn parts(&self) -> impl Iterator<Item = (PartId, PartValue<'_>)> {
        self.0.iter().map(|(id, value)| {
            let value = match value {
                ScopeValue::Uuid(uuid) => PartValue::Uuid(*uuid),
                ScopeValue::I64(value) => PartValue::I64(*value),
                ScopeValue::Bytes(bytes) => PartValue::Bytes(bytes),
            };
            (*id, value)
        })
    }

    /// The key scope of scope `Old`, taking each of its `keys` parts from
    /// `scope` by part ID.
    pub(crate) fn projected<Old: Scope, B: Scope>(scope: &B) -> Result<Self, Error> {
        let values = scope.values();
        check_values(B::PARTS, &values.0)?;
        let keys = keys_parts(Old::PARTS);
        let values = super::project(&keys, &B::PARTS.iter().zip(&values.0))?;

        Ok(Self::keys_of(keys.iter().zip(&values)))
    }

    /// The key scope of a binding without `keys` parts.
    #[cfg(any(feature = "migrate", test))]
    pub(crate) fn empty() -> Self {
        Self(Box::new([]))
    }

    // Parts must be sorted, as `PARTS` is, so equal scopes list their parts in
    // the same order.
    pub(super) fn keys_of<'s>(
        parts: impl Iterator<Item = (&'s PartSpec, &'s PartValue<'s>)>,
    ) -> Self {
        let keys = parts
            .filter(|(spec, _)| spec.role == PartRole::Keys)
            .map(|(spec, value)| {
                let value = match *value {
                    PartValue::Uuid(uuid) => ScopeValue::Uuid(uuid),
                    PartValue::I64(value) => ScopeValue::I64(value),
                    PartValue::Bytes(bytes) => ScopeValue::Bytes(bytes.into()),
                };
                (spec.id(), value)
            });

        Self(keys.collect())
    }
}

fn keys_parts(parts: &[PartSpec]) -> Vec<PartSpec> {
    parts
        .iter()
        .copied()
        .filter(|spec| spec.role == PartRole::Keys)
        .collect()
}
