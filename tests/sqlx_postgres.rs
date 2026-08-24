//! Public-boundary tests for the optional `SQLx` `PostgreSQL` adapter.

#![cfg(feature = "sqlx-postgres")]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexSpec, EncryptionKey, EncryptionKeyring, IndexId, KeyId,
    Keys, Padding, Seal, Sealed, Utf8, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Postgres, Row, Type,
    postgres::{PgArgumentBuffer, PgConnection, PgTypeInfo},
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = key_id!("c0000000-0000-4000-8000-00000000000c");

fn test_keys() -> Keys {
    Keys::new(EncryptionKeyring::new(EncryptionKey::new(KEY_ID, [59; 32]), []).unwrap())
}

struct TestSeal;

impl Seal for TestSeal {
    const ID: cryptbox::SealId = cryptbox::seal_id!("4e2d8b17-6c3a-4f95-8b0e-1a7c9d3f5e26");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct IndexSpec;

impl BlindIndexSpec for IndexSpec {
    type Seal = TestSeal;
    const ID: IndexId = index_id!("d0000000-0000-4000-8000-00000000000d");
    const BITS: u16 = 128;
    const NORMALIZER: &'static str = "exact/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(query.as_bytes().to_vec()))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

fn assert_sqlx_traits<T>()
where
    T: Type<Postgres>,
    for<'q> T: Encode<'q, Postgres>,
    for<'r> T: Decode<'r, Postgres>,
{
}

#[cfg(feature = "migrate")]
fn assert_sqlx_decode<T>()
where
    T: Type<Postgres>,
    for<'r> T: Decode<'r, Postgres>,
{
}

#[test]
fn encrypted_storage_types_map_to_postgres_bytea() {
    assert_sqlx_traits::<Sealed<TestSeal>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();

    // The permissive migration read decodes but deliberately has no Encode:
    // writes always encrypt through `Sealed`.
    #[cfg(feature = "migrate")]
    assert_sqlx_decode::<cryptbox::migrate::MaybeSealed<TestSeal>>();

    let bytea: PgTypeInfo = <Vec<u8> as Type<Postgres>>::type_info();
    assert_eq!(<Sealed<TestSeal> as Type<Postgres>>::type_info(), bytea);
    assert_eq!(
        <BlindIndex<IndexSpec> as Type<Postgres>>::type_info(),
        bytea
    );
}

#[test]
fn sealed_encoding_preserves_the_binary_envelope() {
    let keys = test_keys();
    let bytes = Sealed::<TestSeal>::seal(&"value".to_owned(), &keys)
        .unwrap()
        .into_bytes();
    let ciphertext = Sealed::<TestSeal>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = PgArgumentBuffer::default();

    let result =
        <Sealed<TestSeal> as Encode<'_, Postgres>>::encode_by_ref(&ciphertext, &mut buffer)
            .unwrap();

    assert!(!result.is_null());
    assert_eq!(buffer.as_slice(), bytes.as_slice());
}

/// Round-trips a value through a live `PostgreSQL` server.
///
/// Ignored by default because it needs a server: set `DATABASE_URL` and run with
/// `--ignored`. The Dagger `cryptbox:test:postgres` check binds one and does exactly that.
#[test]
#[ignore = "requires a PostgreSQL server; set DATABASE_URL and run with --ignored"]
fn postgres_round_trips_sealed_values() {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must point at a PostgreSQL server to run this test");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut connection = PgConnection::connect(&url).await.unwrap();
        sqlx::query("CREATE TEMPORARY TABLE secrets (value BYTEA NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();

        let keys = test_keys();
        let value = Sealed::<TestSeal>::seal(&"mark@example.com".to_owned(), &keys).unwrap();
        sqlx::query("INSERT INTO secrets (value) VALUES ($1)")
            .bind(&value)
            .execute(&mut connection)
            .await
            .unwrap();

        let row = sqlx::query("SELECT value FROM secrets")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let sealed: Sealed<TestSeal> = row.try_get("value").unwrap();

        assert_eq!(sealed, value);
        assert_eq!(sealed.open(&keys).unwrap(), "mark@example.com");
    });
}
