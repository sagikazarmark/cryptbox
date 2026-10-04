use sqlx::{
    Decode, Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
};

use crate::{BlindIndex, BlindIndexSpec, ContextKind, Plain, Seal, Sealed};

fn bytea_type_info() -> PgTypeInfo {
    <Vec<u8> as Type<Postgres>>::type_info()
}

fn bytea_compatible(ty: &PgTypeInfo) -> bool {
    <Vec<u8> as Type<Postgres>>::compatible(ty)
}

impl<F: Seal> Type<Postgres> for Plain<F> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<F: Seal> Encode<'_, Postgres> for Plain<F> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let sealed = self.seal_for_column()?;
        buffer.extend_from_slice(sealed.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

impl<'row, F: Seal> Decode<'row, Postgres> for Plain<F> {
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;
        Ok(Self::open_column(bytes)?)
    }
}

impl<F: Seal, C: ContextKind> Type<Postgres> for Sealed<F, C> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<F: Seal, C: ContextKind> Encode<'_, Postgres> for Sealed<F, C> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(self.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'row, F: Seal, C: ContextKind> Decode<'row, Postgres> for Sealed<F, C> {
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
impl<F: Seal> Type<Postgres> for crate::migrate::MaybeSealed<F> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

// Migration-window reads only. Decoding classifies bytes without CryptBox or
// legacy keys; recovery and decryption stay explicit calls. There is no
// `Encode` counterpart: writes always encrypt through `Plain` or `Sealed`.
#[cfg(feature = "migrate")]
impl<'row, F> Decode<'row, Postgres> for crate::migrate::MaybeSealed<F>
where
    F: Seal,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}
