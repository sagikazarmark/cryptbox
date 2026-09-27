use super::{Binding, PartRole, PartSpec, PartValue, check_parts, check_values};
use crate::{Error, PartId};

/// The [`keys`](PartRole::Keys) parts of a binding: the scope that key custody
/// follows.
///
/// Two bindings of the same type share a key scope when their `keys` values
/// are equal, whatever their `index` and bound-only values. A binding without
/// `keys` parts, such as [`FieldOnly`](crate::FieldOnly), has the empty key scope,
/// which every such binding shares. A record never contributes to it.
///
/// A key scope is owned and implements `Hash + Eq`, so an application can use it
/// to cache or look up the keys of each scope. It is the
/// [shred unit](Binding#shredding) when each scope's root keys are stored
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
    /// its parts; see [`Binding`].
    pub fn of<B: Binding>(binding: &B) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let values = binding.values();
        check_values(B::PARTS, &values.0)?;

        Ok(Self::keys_of(B::PARTS.iter().zip(&values.0)))
    }

    /// Returns the key scope of a blind-index query's arguments.
    ///
    /// It equals the key scope of every binding with the same `keys` values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when the arguments' values do not match
    /// the binding's `keys` and `index` parts; see [`Binding::index_values`].
    pub fn of_index<B: Binding>(args: &B::IndexArgs) -> Result<Self, Error> {
        const { check_parts(B::PARTS) };

        let values = B::index_values(args);
        let specs = B::PARTS.iter().filter(|spec| spec.role.scopes_index());
        check_values(specs.clone(), &values.0)?;

        Ok(Self::keys_of(specs.zip(&values.0)))
    }

    // `PARTS` is sorted, so equal scopes list their parts in the same order.
    fn keys_of<'s>(parts: impl Iterator<Item = (&'s PartSpec, &'s PartValue<'s>)>) -> Self {
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
