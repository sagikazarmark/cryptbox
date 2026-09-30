use std::{fmt::Write as _, marker::PhantomData};

use crate::{
    BoundList, BoundValues, Error, PartKind, PartSpec, PartValue,
    binding::{bound_values, from_part_values},
};

// Never appears in an encoded value, so parts split unambiguously.
const SEPARATOR: char = ':';
const UUID_LEN: usize = 36;
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];
// A sign and the 19 digits of `i64::MIN`'s magnitude.
const I64_LEN: usize = 20;

/// The Restate object key of bound list `B`: a strict, canonical text encoding
/// of its values, usually those of a blind index's
/// [partition](crate::BlindIndexSpec::Partition).
///
/// A Virtual Object keyed by bound values, such as one object per org and
/// workspace, reads them back from its object key with [`Self::parse`]. An
/// object key holds one segment per bound value, in list order, separated by
/// `:`, so every object key of one org of an `(OrgId, WorkspaceId)` list starts
/// with that org's [`Self::prefix`].
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
/// the caller for the values it names before binding values to them.
///
/// ```
/// use cryptbox::{Error, TenantId, restate::ObjectKey};
///
/// let acme = TenantId::new("acme")?;
///
/// let key = ObjectKey::<(TenantId,)>::encode(&acme);
/// assert_eq!(key, "61636d65");
/// assert_eq!(ObjectKey::<(TenantId,)>::parse(&key)?, (acme.clone(),));
/// assert_eq!(
///     ObjectKey::<(TenantId,)>::parse("61636D65"),
///     Err(Error::InvalidObjectKey)
/// );
///
/// // Every object key of the tenant starts with its prefix.
/// assert_eq!(ObjectKey::<(TenantId,)>::prefix::<(TenantId,)>(&acme), key);
/// # Ok::<(), cryptbox::Error>(())
/// ```
///
/// A prefix that is not the list's leading types fails the build:
///
/// ```compile_fail,E0080
/// use cryptbox::{TenantId, restate::ObjectKey};
///
/// let acme = TenantId::new("acme").unwrap();
/// let _ = ObjectKey::<()>::prefix::<(TenantId,)>(&acme);
/// ```
pub struct ObjectKey<B>(PhantomData<fn() -> B>);

impl<B: BoundList> ObjectKey<B> {
    /// Encodes bound values as an object key.
    pub fn encode<'a>(values: impl BoundValues<'a, B>) -> String {
        join(bound_values(values).into_iter())
    }

    /// Parses an object key back into the bound values it encodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidObjectKey`] for an object key that is not
    /// exactly the [encoding](Self) of values of `B`: a missing or extra
    /// segment, another spelling of a value, or a value its type cannot hold.
    pub fn parse(key: &str) -> Result<B, Error> {
        let specs = B::PARTS;
        let segments: Vec<_> = if specs.is_empty() && key.is_empty() {
            Vec::new()
        } else {
            key.split(SEPARATOR).collect()
        };
        if segments.len() != specs.len() {
            return Err(Error::InvalidObjectKey);
        }

        let decoded = segments
            .into_iter()
            .zip(specs)
            .map(|(segment, spec)| decode_value(spec.kind(), segment))
            .collect::<Result<Vec<_>, _>>()?;
        let values: Vec<_> = decoded.iter().map(Decoded::part_value).collect();
        // A part type that does not read back exactly what it binds could
        // otherwise accept a second spelling.
        from_part_values::<B>(&values)
            .ok()
            .filter(|_| join(values.iter().copied()) == key)
            .ok_or(Error::InvalidObjectKey)
    }

    /// Returns the object-key prefix of the leading values `values`, of the
    /// leading types `P` of `B`.
    ///
    /// Every object key that starts with those values equals the prefix when
    /// `P` is `B`, and otherwise starts with the prefix and a `:`. Select their
    /// objects in Restate's SQL introspection with
    /// `target_service_key = '<prefix>' OR target_service_key LIKE '<prefix>:%'`;
    /// the encoding never contains a quote or a SQL wildcard. The prefix of `()`
    /// is empty: every object of the service has it, so select them by service
    /// alone.
    #[must_use]
    pub fn prefix<'a, P: BoundList>(values: impl BoundValues<'a, P>) -> String {
        const { check_prefix(P::PARTS, B::PARTS) };

        join(bound_values(values).into_iter())
    }
}

// Panics become build errors in `const` context.
const fn check_prefix(prefix: &[PartSpec], parts: &[PartSpec]) {
    assert!(
        prefix.len() <= parts.len(),
        "an object-key prefix has the leading types of its bound list"
    );
    let mut index = 0;
    while index < prefix.len() {
        assert!(
            u128::from_be_bytes(*prefix[index].id().as_bytes())
                == u128::from_be_bytes(*parts[index].id().as_bytes()),
            "an object-key prefix has the leading types of its bound list"
        );
        index += 1;
    }
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
