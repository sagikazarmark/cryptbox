//! Serde for stored values: bytes in binary formats, and unpadded base64url
//! text in human-readable ones, such as JSON.

use std::{fmt, marker::PhantomData};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};

use crate::{BlindIndex, BlindIndexSpec, ContextKind, Error, Seal, Sealed};

trait DeserializeFromBytes: Sized {
    const EXPECTING: &'static str;

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error>;
}

impl<F: Seal, C: ContextKind> DeserializeFromBytes for Sealed<F, C> {
    const EXPECTING: &'static str =
        "a structurally valid CryptBox envelope, as bytes or unpadded base64url";

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<Spec: BlindIndexSpec> DeserializeFromBytes for BlindIndex<Spec> {
    const EXPECTING: &'static str =
        "a structurally valid CryptBox blind index, as bytes or unpadded base64url";

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

/// Writes `bytes` as bytes, or as unpadded base64url text when the format is
/// human-readable.
fn serialize_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if !serializer.is_human_readable() {
        return serializer.serialize_bytes(bytes);
    }

    let mut text = vec![0; base64::encoded_len(bytes.len(), false).unwrap_or(usize::MAX)];
    let written = URL_SAFE_NO_PAD
        .encode_slice(bytes, &mut text)
        .map_err(serde::ser::Error::custom)?;
    text.truncate(written);
    // Base64 is ASCII.
    let text = String::from_utf8(text).map_err(serde::ser::Error::custom)?;

    serializer.serialize_str(&text)
}

/// Reads bytes, a sequence of bytes, or, in a human-readable format, unpadded
/// base64url text.
fn deserialize_bytes<'de, D, Value>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
    Value: DeserializeFromBytes,
{
    if deserializer.is_human_readable() {
        deserializer.deserialize_any(BytesVisitor(PhantomData))
    } else {
        deserializer.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

struct BytesVisitor<Value>(PhantomData<fn() -> Value>);

impl<'de, Value: DeserializeFromBytes> Visitor<'de> for BytesVisitor<Value> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Value::EXPECTING)
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut bytes = vec![0; base64::decoded_len_estimate(text.len())];
        let read = URL_SAFE_NO_PAD
            .decode_slice(text, &mut bytes)
            .map_err(|_| E::custom(Error::InvalidEnvelope))?;
        bytes.truncate(read);

        Value::deserialize_from_bytes(bytes).map_err(E::custom)
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Value::deserialize_from_bytes(bytes.to_vec()).map_err(E::custom)
    }

    fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Value::deserialize_from_bytes(bytes).map_err(E::custom)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Vec::new();

        while let Some(byte) = sequence.next_element()? {
            bytes.push(byte);
        }

        Value::deserialize_from_bytes(bytes).map_err(A::Error::custom)
    }
}

impl<F: Seal, C: ContextKind> Serialize for Sealed<F, C> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.as_bytes(), serializer)
    }
}

impl<'de, F: Seal, C: ContextKind> Deserialize<'de> for Sealed<F, C> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bytes(deserializer)
    }
}

impl<Spec> Serialize for BlindIndex<Spec> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.as_bytes(), serializer)
    }
}

impl<'de, Spec: BlindIndexSpec> Deserialize<'de> for BlindIndex<Spec> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_bytes(deserializer)
    }
}
