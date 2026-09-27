//! Public-boundary tests for the optional `SQLx` `PostgreSQL` adapter.

#![cfg(feature = "sqlx-postgres")]

use std::sync::Once;

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexRef, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionKeyProvider, Field, GlobalKeyContext, GlobalProviders, IndexId,
    KeyContext, KeyId, LocalEncryptionKeyring, Padding, Utf8, encrypt, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Postgres, Row, Type,
    postgres::{PgArgumentBuffer, PgConnection, PgTypeInfo},
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = key_id!("c0000000-0000-4000-8000-00000000000c");

/// Installs the process-wide keys that automatic encoding and decoding read.
///
/// Each integration-test binary is its own process, so the global is isolated
/// from other test files; every test here shares the same fixed keyring.
fn install_keys() -> &'static dyn EncryptionKeyProvider {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let keys = LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [59; 32]), []).unwrap();
        GlobalKeyContext::install(GlobalProviders::new(keys)).unwrap();
    });

    GlobalKeyContext::encryption_keys().unwrap()
}

struct TestField;

impl Field for TestField {
    const ID: cryptbox::FieldId = cryptbox::field_id!("4e2d8b17-6c3a-4f95-8b0e-1a7c9d3f5e26");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
}

struct IndexSpec;

impl BlindIndexSpec for IndexSpec {
    type Field = TestField;
    const ID: IndexId = index_id!("d0000000-0000-4000-8000-00000000000d");
    const BITS: u16 = 128;
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
    assert_sqlx_traits::<Encrypted<TestField>>();
    assert_sqlx_traits::<Ciphertext<TestField>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    // The permissive migration read decodes but deliberately has no Encode:
    // writes always encrypt through `Encrypted` or `Prepared`.
    #[cfg(feature = "migrate")]
    assert_sqlx_decode::<cryptbox::migrate::MaybeEncrypted<TestField>>();

    let bytea: PgTypeInfo = <Vec<u8> as Type<Postgres>>::type_info();
    assert_eq!(<Encrypted<TestField> as Type<Postgres>>::type_info(), bytea);
    assert_eq!(
        <Ciphertext<TestField> as Type<Postgres>>::type_info(),
        bytea
    );
    assert_eq!(
        <BlindIndex<IndexSpec> as Type<Postgres>>::type_info(),
        bytea
    );
}

#[test]
fn sqlx_encode_encrypts_plaintext_into_an_owned_argument_buffer() {
    install_keys();
    let value = Encrypted::<TestField>::new("mark@example.com".to_owned());
    let mut buffer = PgArgumentBuffer::default();

    let result =
        <Encrypted<TestField> as Encode<'_, Postgres>>::encode_by_ref(&value, &mut buffer).unwrap();

    assert!(!result.is_null());
    assert!(buffer.starts_with(b"CBX\0"));
}

#[test]
fn typed_ciphertext_encoding_preserves_the_binary_envelope() {
    let keys = install_keys();
    let bytes = encrypt(TestField::ID, b"value", keys).unwrap();
    let ciphertext = Ciphertext::<TestField>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = PgArgumentBuffer::default();

    let result =
        <Ciphertext<TestField> as Encode<'_, Postgres>>::encode_by_ref(&ciphertext, &mut buffer)
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
fn postgres_round_trips_ciphertext_and_decrypts_encrypted_values() {
    install_keys();
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

        let value = Encrypted::<TestField>::new("mark@example.com".to_owned());
        sqlx::query("INSERT INTO secrets (value) VALUES ($1)")
            .bind(&value)
            .execute(&mut connection)
            .await
            .unwrap();

        let row = sqlx::query("SELECT value FROM secrets")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let ciphertext: Ciphertext<TestField> = row.try_get("value").unwrap();
        let decrypted: Encrypted<TestField> = row.try_get("value").unwrap();

        assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
        assert_eq!(decrypted.expose_secret(), "mark@example.com");
    });
}
