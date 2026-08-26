use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};

use crate::{BlindIndex, BlindIndexMetadata, Ciphertext, Error};

trait DeserializeFromBytes: Sized {
    const EXPECTING: &'static str;

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error>;
}

impl<T, Profile> DeserializeFromBytes for Ciphertext<T, Profile> {
    const EXPECTING: &'static str = "a structurally valid CryptBox ciphertext envelope";

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl<Spec: BlindIndexMetadata> DeserializeFromBytes for BlindIndex<Spec> {
    const EXPECTING: &'static str = "a structurally valid CryptBox blind index";

    fn deserialize_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

struct BytesVisitor<Value>(PhantomData<fn() -> Value>);

impl<'de, Value: DeserializeFromBytes> Visitor<'de> for BytesVisitor<Value> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Value::EXPECTING)
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

impl<T, Profile> Serialize for Ciphertext<T, Profile> {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de, T, Profile> Deserialize<'de> for Ciphertext<T, Profile> {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

impl<Spec> Serialize for BlindIndex<Spec> {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de, Spec: BlindIndexMetadata> Deserialize<'de> for BlindIndex<Spec> {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor(PhantomData))
    }
}
