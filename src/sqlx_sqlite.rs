use std::borrow::Cow;

use sqlx::{
    Decode, Encode, Sqlite, Type,
    encode::IsNull,
    error::BoxDynError,
    sqlite::{SqliteArgumentValue, SqliteTypeInfo, SqliteValueRef},
};

use crate::{BlindIndex, BlindIndexRef, BlindIndexSpec, Ciphertext, Encrypted, Field};

fn blob_type_info() -> SqliteTypeInfo {
    <Vec<u8> as Type<Sqlite>>::type_info()
}

fn blob_compatible(ty: &SqliteTypeInfo) -> bool {
    <Vec<u8> as Type<Sqlite>>::compatible(ty)
}

impl<F: Field> Type<Sqlite> for Encrypted<F> {
    fn type_info() -> SqliteTypeInfo {
        blob_type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        blob_compatible(ty)
    }
}

impl<F: Field> Type<Sqlite> for Ciphertext<F> {
    fn type_info() -> SqliteTypeInfo {
        blob_type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        blob_compatible(ty)
    }
}

impl<Spec> Type<Sqlite> for BlindIndex<Spec> {
    fn type_info() -> SqliteTypeInfo {
        blob_type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        blob_compatible(ty)
    }
}

impl<Spec> Type<Sqlite> for BlindIndexRef<'_, Spec> {
    fn type_info() -> SqliteTypeInfo {
        blob_type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        blob_compatible(ty)
    }
}

impl<'q, F> Encode<'q, Sqlite> for Encrypted<F>
where
    F: Field,
{
    fn encode_by_ref(
        &self,
        buffer: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, BoxDynError> {
        let ciphertext = self.encrypt()?;
        buffer.push(SqliteArgumentValue::Blob(Cow::Owned(
            ciphertext.into_bytes(),
        )));

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

impl<'q, F: Field> Encode<'q, Sqlite> for Ciphertext<F> {
    fn encode_by_ref(
        &self,
        buffer: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, BoxDynError> {
        buffer.push(SqliteArgumentValue::Blob(Cow::Owned(
            self.as_bytes().to_vec(),
        )));

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'q, Spec> Encode<'q, Sqlite> for BlindIndex<Spec> {
    fn encode_by_ref(
        &self,
        buffer: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, BoxDynError> {
        buffer.push(SqliteArgumentValue::Blob(Cow::Owned(
            self.as_bytes().to_vec(),
        )));

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'q, Spec> Encode<'q, Sqlite> for BlindIndexRef<'_, Spec> {
    fn encode_by_ref(
        &self,
        buffer: &mut Vec<SqliteArgumentValue<'q>>,
    ) -> Result<IsNull, BoxDynError> {
        buffer.push(SqliteArgumentValue::Blob(Cow::Owned(
            self.as_bytes().to_vec(),
        )));

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'row, F> Decode<'row, Sqlite> for Encrypted<F>
where
    F: Field,
{
    fn decode(value: SqliteValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Sqlite>>::decode(value)?;
        let ciphertext = Ciphertext::<F>::from_bytes(bytes)?;

        Ok(ciphertext.decrypt()?)
    }
}

impl<'row, F: Field> Decode<'row, Sqlite> for Ciphertext<F> {
    fn decode(value: SqliteValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Sqlite>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

impl<'row, Spec> Decode<'row, Sqlite> for BlindIndex<Spec>
where
    Spec: BlindIndexSpec,
{
    fn decode(value: SqliteValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Sqlite>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

#[cfg(feature = "migrate")]
impl<F: Field> Type<Sqlite> for crate::migrate::MaybeEncrypted<F> {
    fn type_info() -> SqliteTypeInfo {
        blob_type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        blob_compatible(ty)
    }
}

// Migration-window reads only. Decoding classifies bytes without CryptBox or
// legacy keys; recovery and decryption stay explicit calls. There is no
// `Encode` counterpart: writes always encrypt through `Encrypted` or
// `Prepared`.
#[cfg(feature = "migrate")]
impl<'row, F> Decode<'row, Sqlite> for crate::migrate::MaybeEncrypted<F>
where
    F: Field,
{
    fn decode(value: SqliteValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Sqlite>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}
