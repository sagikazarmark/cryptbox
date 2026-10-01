//! Public-boundary tests for the optional `SQLx` `PostgreSQL` adapter.

#![cfg(feature = "sqlx-postgres")]

use std::sync::LazyLock;

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexRef, BlindIndexSpec, ColumnKeys, EncryptionKey,
    EncryptionKeyring, Error, IndexId, KeyId, Keys, Padding, Plain, Seal, Sealed, Utf8, index_id,
    key_id, keys,
};
use sqlx::{
    Connection, Decode, Encode, Postgres, Row, Type,
    postgres::{PgArgumentBuffer, PgConnection, PgTypeInfo},
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = key_id!("c0000000-0000-4000-8000-00000000000c");

/// The automatic columns' key source. No test in this binary installs the
/// global, so every column round trip here proves the column reads `K`.
struct TestKeys;

impl ColumnKeys for TestKeys {
    fn keys() -> Result<&'static Keys, Error> {
        static KEYS: LazyLock<Keys> = LazyLock::new(|| {
            Keys::new(EncryptionKeyring::new(EncryptionKey::new(KEY_ID, [59; 32]), []).unwrap())
        });

        Ok(&*KEYS)
    }
}

struct TestSeal;

impl Seal for TestSeal {
    const ID: cryptbox::SealId = cryptbox::seal_id!("4e2d8b17-6c3a-4f95-8b0e-1a7c9d3f5e26");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Record = ();
    type Indexes = ();
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

fn assert_sqlx_encode<T>()
where
    T: Type<Postgres>,
    for<'q> T: Encode<'q, Postgres>,
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
    assert_sqlx_traits::<Plain<TestSeal, TestKeys>>();
    assert_sqlx_traits::<Sealed<TestSeal>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    // The permissive migration read decodes but deliberately has no Encode:
    // writes always encrypt through `Plain`, `Sealed`, or `Prepared`.
    #[cfg(feature = "migrate")]
    assert_sqlx_decode::<cryptbox::migrate::MaybeEncrypted<TestSeal>>();

    let bytea: PgTypeInfo = <Vec<u8> as Type<Postgres>>::type_info();
    assert_eq!(
        <Plain<TestSeal, TestKeys> as Type<Postgres>>::type_info(),
        bytea
    );
    assert_eq!(<Sealed<TestSeal> as Type<Postgres>>::type_info(), bytea);
    assert_eq!(
        <BlindIndex<IndexSpec> as Type<Postgres>>::type_info(),
        bytea
    );
}

#[test]
fn sqlx_encode_encrypts_plaintext_into_an_owned_argument_buffer() {
    let value = Plain::<TestSeal, TestKeys>::new("mark@example.com".to_owned());
    let mut buffer = PgArgumentBuffer::default();

    let result =
        <Plain<TestSeal, TestKeys> as Encode<'_, Postgres>>::encode_by_ref(&value, &mut buffer)
            .unwrap();

    assert!(!result.is_null());
    assert!(buffer.starts_with(b"CBX\0"));
}

#[test]
fn sealed_encoding_preserves_the_binary_envelope() {
    let keys = TestKeys::keys().unwrap();
    let bytes = Sealed::<TestSeal>::seal(&"value".to_owned(), (), keys)
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
fn postgres_round_trips_sealed_values_and_opens_plain_columns() {
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

        let value = Plain::<TestSeal, TestKeys>::new("mark@example.com".to_owned());
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
        let opened: Plain<TestSeal, TestKeys> = row.try_get("value").unwrap();

        assert!(sealed.as_bytes().starts_with(b"CBX\0"));
        assert_eq!(opened.expose_secret(), "mark@example.com");
        // The column used `TestKeys`; the global was never installed.
        assert_eq!(
            sealed.open((), TestKeys::keys().unwrap()).unwrap(),
            "mark@example.com"
        );
        assert_eq!(keys::installed().unwrap_err(), Error::KeysNotInstalled);
    });
}

#[test]
fn postgres_default_column_fails_closed_without_installed_keys() {
    let value = Plain::<TestSeal>::new("mark@example.com");
    let mut buffer = PgArgumentBuffer::default();

    let Err(error) = <Plain<TestSeal> as Encode<'_, Postgres>>::encode_by_ref(&value, &mut buffer)
    else {
        panic!("encoding without installed keys must fail");
    };

    assert_eq!(
        error.downcast_ref::<Error>(),
        Some(&Error::KeysNotInstalled)
    );
    assert!(buffer.is_empty());
}
