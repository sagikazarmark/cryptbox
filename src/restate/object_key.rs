use std::{fmt::Write as _, marker::PhantomData};

use crate::{
    Binding, Error, FromIndexValues, KeyScope, PartKind, PartRole, PartSpec, PartValue,
    binding::check_values,
};

// Never appears in an encoded value, so parts split unambiguously.
const SEPARATOR: char = ':';
const UUID_LEN: usize = 36;
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];
// A sign and the 19 digits of `i64::MIN`'s magnitude.
const I64_LEN: usize = 20;

/// The Restate object key of binding `B`: a strict, canonical text encoding of
/// its [index arguments](Binding::IndexArgs).
///
/// A Virtual Object keyed by a binding's index arguments, such as one object per
/// org and workspace, reads them back from its object key with [`Self::parse`].
/// An object key holds one part per [`keys`](PartRole::Keys) and
/// [`index`](PartRole::Index) part, separated by `:`. The `keys` parts come
/// first, then the `index` parts, each in [`PARTS`](Binding::PARTS) order, so
/// every object key of a key scope starts with that key scope's
/// [`Self::prefix`]. Bound-only parts are never part of an object key.
///
/// | Kind | Encoding | Example |
/// | --- | --- | --- |
/// | uuid | 36 characters, lowercase and hyphenated | `01923a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b` |
/// | i64 | a sign and 19 zero-padded digits | `+0000000000000000042`, `-0000000000000000007` |
/// | bytes | lowercase hex | `61636d65` |
///
/// Parsing accepts exactly one spelling of each value and rejects every other
/// with [`Error::InvalidObjectKey`], which Restate handlers treat as terminal.
/// An object key is plaintext wherever Restate shows it: in the journal, the
/// admin API, and logs. Never key an object by a value that must stay secret.
///
/// An object key is only as trustworthy as the caller that chose it. Authorize
/// the caller for the index arguments it names before binding values to them.
///
/// ```
/// use cryptbox::{Error, KeyScope, Tenant, TenantId, restate::ObjectKey};
///
/// let acme = Tenant(TenantId::new("acme")?);
///
/// let key = ObjectKey::<Tenant>::encode(&acme)?;
/// assert_eq!(key, "61636d65");
/// assert_eq!(ObjectKey::<Tenant>::parse(&key)?, acme);
/// assert_eq!(ObjectKey::<Tenant>::parse("61636D65"), Err(Error::InvalidObjectKey));
///
/// // Every object key of the tenant's key scope starts with its prefix.
/// assert_eq!(ObjectKey::<Tenant>::prefix(&KeyScope::of(&acme)?)?, key);
/// # Ok::<(), cryptbox::Error>(())
/// ```
pub struct ObjectKey<B>(PhantomData<fn() -> B>);

impl<B: Binding> ObjectKey<B> {
    /// Encodes index arguments as an object key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when the arguments' values do not
    /// match the binding's `keys` and `index` parts; see
    /// [`Binding::index_values`].
    pub fn encode(args: &B::IndexArgs) -> Result<String, Error> {
        let values = B::index_values(args);
        let values = values.as_slice();
        check_values(index_specs::<B>(), values)?;

        Ok(join(
            key_order::<B>()
                .into_iter()
                .map(|position| values[position]),
        ))
    }

    /// Parses an object key back into the index arguments it encodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidObjectKey`] for an object key that is not
    /// exactly the [encoding](Self) of index arguments of `B`: a missing or
    /// extra part, parts out of order, another spelling of a value, or a value
    /// the binding cannot hold, such as an empty `keys` value.
    pub fn parse(key: &str) -> Result<B::IndexArgs, Error>
    where
        B: FromIndexValues,
    {
        let specs: Vec<_> = index_specs::<B>().collect();
        let segments: Vec<_> = if specs.is_empty() && key.is_empty() {
            Vec::new()
        } else {
            key.split(SEPARATOR).collect()
        };
        if segments.len() != specs.len() {
            return Err(Error::InvalidObjectKey);
        }

        let mut decoded = vec![Decoded::I64(0); specs.len()];
        for (segment, position) in segments.into_iter().zip(key_order::<B>()) {
            decoded[position] = decode_value(specs[position].kind(), segment)?;
        }
        let values: Vec<_> = decoded.iter().map(Decoded::part_value).collect();

        let args = check_values(specs, &values)
            .and_then(|()| B::from_index_values(&values))
            .map_err(|_| Error::InvalidObjectKey)?;
        // A part type that does not read back exactly what it binds could
        // otherwise accept a second spelling.
        match Self::encode(&args) {
            Ok(canonical) if canonical == key => Ok(args),
            _ => Err(Error::InvalidObjectKey),
        }
    }

    /// Returns the object-key prefix of a key scope: its `keys` parts.
    ///
    /// Every object key of the key scope equals the prefix when `B` has no
    /// `index` parts, and otherwise starts with the prefix and a `:`. Select a
    /// key scope's objects in Restate's SQL introspection with
    /// `target_service_key = '<prefix>' OR target_service_key LIKE '<prefix>:%'`;
    /// the encoding never contains a quote or a SQL wildcard.
    ///
    /// A binding without `keys` parts has one key scope, the empty one, and its
    /// prefix is empty: every object of the service belongs to it, so select
    /// them by service alone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidBinding`] when `scope` is not a key scope of `B`.
    pub fn prefix(scope: &KeyScope) -> Result<String, Error> {
        let specs = B::PARTS.iter().filter(|spec| spec.role() == PartRole::Keys);
        let values: Vec<_> = scope.parts().collect();
        let matches = values.len() == specs.clone().count()
            && specs
                .zip(&values)
                .all(|(spec, (id, value))| *id == spec.id() && value.kind() == spec.kind());
        if !matches {
            return Err(Error::InvalidBinding);
        }

        Ok(join(values.into_iter().map(|(_, value)| value)))
    }
}

/// The `keys` and `index` parts of `B`, in `PARTS` order.
fn index_specs<B: Binding>() -> impl Iterator<Item = &'static PartSpec> + Clone {
    B::PARTS
        .iter()
        .filter(|spec| matches!(spec.role(), PartRole::Keys | PartRole::Index))
}

/// The positions among [`index_specs`] in object-key order: `keys` parts first.
fn key_order<B: Binding>() -> Vec<usize> {
    let roles: Vec<_> = index_specs::<B>().map(PartSpec::role).collect();
    let positions_of = |role| {
        roles
            .iter()
            .enumerate()
            .filter(move |&(_, &other)| other == role)
            .map(|(position, _)| position)
    };

    positions_of(PartRole::Keys)
        .chain(positions_of(PartRole::Index))
        .collect()
}

/// Encodes `values` in order, separated by `:`.
fn join<'v>(values: impl Iterator<Item = PartValue<'v>>) -> String {
    let mut encoded = String::new();
    for (count, value) in values.enumerate() {
        if count > 0 {
            encoded.push(SEPARATOR);
        }
        encode_value(value, &mut encoded);
    }

    encoded
}

fn encode_value(value: PartValue<'_>, encoded: &mut String) {
    match value {
        PartValue::Uuid(uuid) => {
            let hex = hex::encode(uuid);
            for (position, char) in hex.chars().enumerate() {
                if matches!(position, 8 | 12 | 16 | 20) {
                    encoded.push('-');
                }
                encoded.push(char);
            }
        }
        PartValue::I64(value) => {
            let sign = if value < 0 { '-' } else { '+' };
            // Writing to a `String` cannot fail.
            let _ = write!(encoded, "{sign}{:019}", value.unsigned_abs());
        }
        PartValue::Bytes(bytes) => encoded.push_str(&hex::encode(bytes)),
    }
}

/// An owned, decoded part value.
#[derive(Clone)]
enum Decoded {
    Uuid([u8; 16]),
    I64(i64),
    Bytes(Vec<u8>),
}

impl Decoded {
    fn part_value(&self) -> PartValue<'_> {
        match self {
            Self::Uuid(uuid) => PartValue::Uuid(*uuid),
            Self::I64(value) => PartValue::I64(*value),
            Self::Bytes(bytes) => PartValue::Bytes(bytes),
        }
    }
}

fn decode_value(kind: PartKind, segment: &str) -> Result<Decoded, Error> {
    let decoded = match kind {
        PartKind::Uuid => decode_uuid(segment).map(Decoded::Uuid),
        PartKind::I64 => decode_i64(segment).map(Decoded::I64),
        PartKind::Bytes => decode_hex(segment).map(Decoded::Bytes),
    };

    decoded.ok_or(Error::InvalidObjectKey)
}

fn decode_uuid(segment: &str) -> Option<[u8; 16]> {
    let bytes = segment.as_bytes();
    if bytes.len() != UUID_LEN || UUID_HYPHENS.iter().any(|&hyphen| bytes[hyphen] != b'-') {
        return None;
    }
    let hex: String = segment
        .char_indices()
        .filter(|(position, _)| !UUID_HYPHENS.contains(position))
        .map(|(_, char)| char)
        .collect();

    decode_hex(&hex)?.try_into().ok()
}

fn decode_i64(segment: &str) -> Option<i64> {
    let (sign, digits) = segment.split_at_checked(1)?;
    if segment.len() != I64_LEN || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let magnitude: u64 = digits.parse().ok()?;

    match sign {
        "+" => i64::try_from(magnitude).ok(),
        // Zero is always `+`.
        "-" if magnitude > 0 => 0_i64.checked_sub_unsigned(magnitude),
        _ => None,
    }
}

/// Decodes lowercase hex only, so each byte string has one spelling.
fn decode_hex(segment: &str) -> Option<Vec<u8>> {
    let lowercase = segment
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));

    lowercase.then(|| hex::decode(segment).ok()).flatten()
}
