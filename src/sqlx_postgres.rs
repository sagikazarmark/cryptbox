use sqlx::{
    Decode, Encode, Postgres, Type,
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
};

use crate::{
    Binding, BlindIndex, BlindIndexMetadata, BlindIndexRef, Ciphertext, Encrypted,
    EncryptionProfile,
};

fn bytea_type_info() -> PgTypeInfo {
    <Vec<u8> as Type<Postgres>>::type_info()
}

fn bytea_compatible(ty: &PgTypeInfo) -> bool {
    <Vec<u8> as Type<Postgres>>::compatible(ty)
}

impl<T, Profile> Type<Postgres> for Encrypted<T, Profile> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<T, Profile> Encode<'_, Postgres> for Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let ciphertext = self.encrypt()?;
        buffer.extend_from_slice(ciphertext.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        0
    }
}

impl<'row, T, Profile> Decode<'row, Postgres> for Encrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;
        let ciphertext = Ciphertext::<T, Profile>::from_bytes(bytes)?;

        Ok(ciphertext.decrypt()?)
    }
}

impl<T, Profile> Type<Postgres> for Ciphertext<T, Profile> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

impl<T, Profile> Encode<'_, Postgres> for Ciphertext<T, Profile> {
    fn encode_by_ref(&self, buffer: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buffer.extend_from_slice(self.as_bytes());

        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<'row, T, Profile> Decode<'row, Postgres> for Ciphertext<T, Profile> {
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
    Spec: BlindIndexMetadata,
{
    fn decode(value: PgValueRef<'row>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<'row, Postgres>>::decode(value)?;

        Ok(Self::from_bytes(bytes)?)
    }
}

#[cfg(feature = "migrate")]
impl<T, Profile> Type<Postgres> for crate::migrate::MaybeEncrypted<T, Profile> {
    fn type_info() -> PgTypeInfo {
        bytea_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        bytea_compatible(ty)
    }
}

// Migration-window reads only. Decoding classifies bytes without CryptBox or
// legacy keys; recovery and decryption stay explicit calls. There is no
// `Encode` counterpart: writes always encrypt through `Encrypted` or
// `Prepared`.
#[cfg(feature = "migrate")]
impl<'row, T, Profile> Decode<'row, Postgres> for crate::migrate::MaybeEncrypted<T, Profile>
where
    Profile: EncryptionProfile<T>,
    Profile::Binding: Binding<Context = ()>,
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
