//! Public-boundary tests for the optional `SQLx` `PostgreSQL` adapter.

#![cfg(feature = "sqlx-postgres")]

use std::sync::OnceLock;

use cryptbox::{
    BlindIndex, BlindIndexMetadata, BlindIndexRef, Ciphertext, Encrypted, EncryptionKey,
    EncryptionKeyProvider, EncryptionProfile, IndexId, KeyContext, KeyId, KeyProviderError,
    LocalEncryptionKeyring, Unbound, Utf8, encrypt, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Postgres, Row, Type,
    postgres::{PgArgumentBuffer, PgConnection, PgTypeInfo},
};

const KEY_ID: KeyId = key_id!("c0000000-0000-4000-8000-00000000000c");

struct TestKeys;

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        static KEYS: OnceLock<LocalEncryptionKeyring> = OnceLock::new();
        Ok(KEYS.get_or_init(|| {
            LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [59; 32]), []).unwrap()
        }))
    }

    fn blind_index_keys() -> Result<&'static dyn cryptbox::BlindIndexKeyProvider, KeyProviderError>
    {
        Err(KeyProviderError::Unavailable)
    }
}

struct Profile;

impl EncryptionProfile<String> for Profile {
    type Binding = Unbound;
    type Codec = Utf8;
    type Keys = TestKeys;
    type Padding = cryptbox::NoPadding;
}

struct IndexSpec;

impl BlindIndexMetadata for IndexSpec {
    const BITS: usize = 128;
    const ID: IndexId = index_id!("d0000000-0000-4000-8000-00000000000d");
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
    assert_sqlx_traits::<Encrypted<String, Profile>>();
    assert_sqlx_traits::<Ciphertext<String, Profile>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    // The permissive migration read decodes but deliberately has no Encode:
    // writes always encrypt through `Encrypted` or `Prepared`.
    #[cfg(feature = "migrate")]
    assert_sqlx_decode::<cryptbox::migrate::MaybeEncrypted<String, Profile>>();

    let bytea: PgTypeInfo = <Vec<u8> as Type<Postgres>>::type_info();
    assert_eq!(
        <Encrypted<String, Profile> as Type<Postgres>>::type_info(),
        bytea
    );
    assert_eq!(
        <Ciphertext<String, Profile> as Type<Postgres>>::type_info(),
        bytea
    );
    assert_eq!(
        <BlindIndex<IndexSpec> as Type<Postgres>>::type_info(),
        bytea
    );
}

#[test]
fn sqlx_encode_encrypts_plaintext_into_an_owned_argument_buffer() {
    let value = Encrypted::<_, Profile>::new("mark@example.com".to_owned());
    let mut buffer = PgArgumentBuffer::default();

    let result =
        <Encrypted<String, Profile> as Encode<'_, Postgres>>::encode_by_ref(&value, &mut buffer)
            .unwrap();

    assert!(!result.is_null());
    assert!(buffer.starts_with(b"CBX\0"));
}

#[test]
fn typed_ciphertext_encoding_preserves_the_binary_envelope() {
    let keys = TestKeys::encryption_keys().unwrap();
    let bytes = encrypt::<Unbound>(b"value", &(), keys).unwrap();
    let ciphertext = Ciphertext::<String, Profile>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = PgArgumentBuffer::default();

    let result = <Ciphertext<String, Profile> as Encode<'_, Postgres>>::encode_by_ref(
        &ciphertext,
        &mut buffer,
    )
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

        let value = Encrypted::<_, Profile>::new("mark@example.com".to_owned());
        sqlx::query("INSERT INTO secrets (value) VALUES ($1)")
            .bind(&value)
            .execute(&mut connection)
            .await
            .unwrap();

        let row = sqlx::query("SELECT value FROM secrets")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let ciphertext: Ciphertext<String, Profile> = row.try_get("value").unwrap();
        let decrypted: Encrypted<String, Profile> = row.try_get("value").unwrap();

        assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
        assert_eq!(decrypted.expose_secret(), "mark@example.com");
    });
}
