//! Public-boundary tests for the optional `SQLx` `SQLite` adapter.

#![cfg(feature = "sqlx-sqlite")]

use std::sync::OnceLock;

use cryptbox::{
    BlindIndex, BlindIndexMetadata, BlindIndexRef, Ciphertext, Encrypted, EncryptionKey,
    EncryptionKeyProvider, EncryptionProfile, IndexId, KeyContext, KeyId, KeyProviderError,
    LocalEncryptionKeyring, Unbound, Utf8, encrypt, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Row, Sqlite, Type,
    sqlite::{SqliteArgumentValue, SqliteConnection, SqliteTypeInfo},
};

const KEY_ID: KeyId = key_id!("f0000000-0000-4000-8000-00000000000f");

struct TestKeys;

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, KeyProviderError> {
        static KEYS: OnceLock<LocalEncryptionKeyring> = OnceLock::new();
        Ok(KEYS.get_or_init(|| {
            LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [71; 32]), []).unwrap()
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
    const ID: IndexId = index_id!("e0000000-0000-4000-8000-00000000000e");
}

fn assert_sqlx_traits<T>()
where
    T: Type<Sqlite>,
    for<'q> T: Encode<'q, Sqlite>,
    for<'r> T: Decode<'r, Sqlite>,
{
}

fn assert_sqlx_encode<T>()
where
    T: Type<Sqlite>,
    for<'q> T: Encode<'q, Sqlite>,
{
}

fn only_blob<'a>(buffer: &'a [SqliteArgumentValue<'_>]) -> &'a [u8] {
    let [SqliteArgumentValue::Blob(bytes)] = buffer else {
        panic!("expected exactly one SQLite BLOB argument");
    };
    bytes
}

#[test]
fn encrypted_storage_types_map_to_sqlite_blob() {
    assert_sqlx_traits::<Encrypted<String, Profile>>();
    assert_sqlx_traits::<Ciphertext<String, Profile>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();

    let blob: SqliteTypeInfo = <Vec<u8> as Type<Sqlite>>::type_info();
    assert_eq!(
        <Encrypted<String, Profile> as Type<Sqlite>>::type_info(),
        blob
    );
    assert_eq!(
        <Ciphertext<String, Profile> as Type<Sqlite>>::type_info(),
        blob
    );
    assert_eq!(<BlindIndex<IndexSpec> as Type<Sqlite>>::type_info(), blob);
}

#[test]
fn sqlite_encode_encrypts_plaintext_into_an_owned_blob() {
    assert_sqlx_encode::<Encrypted<String, Profile>>();
    assert_sqlx_encode::<Ciphertext<String, Profile>>();
    assert_sqlx_encode::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    let value = Encrypted::<_, Profile>::new("mark@example.com".to_owned());
    let mut buffer = Vec::new();

    let result =
        <Encrypted<String, Profile> as Encode<'_, Sqlite>>::encode_by_ref(&value, &mut buffer)
            .unwrap();

    assert!(!result.is_null());
    assert!(only_blob(&buffer).starts_with(b"CBX\0"));
}

#[test]
fn sqlite_ciphertext_encoding_preserves_the_binary_envelope() {
    let keys = TestKeys::encryption_keys().unwrap();
    let bytes = encrypt::<Unbound>(b"value", &(), keys).unwrap();
    let ciphertext = Ciphertext::<String, Profile>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = Vec::new();

    let result = <Ciphertext<String, Profile> as Encode<'_, Sqlite>>::encode_by_ref(
        &ciphertext,
        &mut buffer,
    )
    .unwrap();

    assert!(!result.is_null());
    assert_eq!(only_blob(&buffer), bytes);
}

#[test]
fn sqlite_round_trips_ciphertext_and_decrypts_encrypted_values() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE secrets (value BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();

        let value = Encrypted::<_, Profile>::new("mark@example.com".to_owned());
        sqlx::query("INSERT INTO secrets (value) VALUES (?)")
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
