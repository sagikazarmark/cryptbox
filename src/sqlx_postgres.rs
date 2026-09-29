use sqlx::{
    Decode, Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
};

use crate::{
    BlindIndex, BlindIndexRef, BlindIndexSpec, ColumnKeys, Field, FieldOnly, Plain, Sealed,
};

fn bytea_type_info() -> PgTypeInfo {
    <Vec<u8> as Type<Postgres>>::type_info()
}

fn bytea_compatible(ty: &PgTypeInfo) -> bool {
    <Vec<u8> as Type<Postgres>>::compatible(ty)
}

impl<F, K> Type<Postgres> for Plain<F, K>
where
    F: Field<Binding = FieldOnly, Indexes = ()>,
    K: ColumnKeys,
{
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<F, K> Encode<'_, Postgres> for Plain<F, K>
where
    F: Field<Binding = FieldOnly, Indexes = ()>,
    K: ColumnKeys,
{
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let sealed = self.seal_for_column()?;
        buffer.extend_from_slice(sealed.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

impl<'row, F, K> Decode<'row, Postgres> for Plain<F, K>
where
    F: Field<Binding = FieldOnly, Indexes = ()>,
    K: ColumnKeys,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;
        Ok(Self::open_column(bytes)?)
    }
}

impl<F: Field> Type<Postgres> for Sealed<F> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<F: Field> Encode<'_, Postgres> for Sealed<F> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(self.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'row, F: Field> Decode<'row, Postgres> for Sealed<F> {
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

impl<Spec> Type<Postgres> for BlindIndex<Spec> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<Spec> Encode<'_, Postgres> for BlindIndex<Spec> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(self.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'row, Spec> Decode<'row, Postgres> for BlindIndex<Spec>
where
    Spec: BlindIndexSpec,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

#[cfg(feature = "migrate")]
impl<F: Field> Type<Postgres> for crate::migrate::MaybeEncrypted<F> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

// Migration-window reads only. Decoding classifies bytes without CryptBox or
// legacy keys; recovery and decryption stay explicit calls. There is no
// `Encode` counterpart: writes always encrypt through `Plain`, `Sealed`, or
// `Prepared`.
#[cfg(feature = "migrate")]
impl<'row, F> Decode<'row, Postgres> for crate::migrate::MaybeEncrypted<F>
where
    F: Field,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

impl<Spec> Type<Postgres> for BlindIndexRef<'_, Spec> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<Spec> Encode<'_, Postgres> for BlindIndexRef<'_, Spec> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(self.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}
