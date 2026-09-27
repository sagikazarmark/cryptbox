//! Public-boundary tests for the optional `SQLx` `SQLite` adapter.

#![cfg(feature = "sqlx-sqlite")]

use std::sync::LazyLock;

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexRef, BlindIndexSpec, Ciphertext, Encrypted,
    EncryptionKey, EncryptionKeyProvider, Error, Field, IndexId, KeyContext, KeyId,
    LocalEncryptionKeyring, Padding, Utf8, encrypt, index_id, key_id, keys,
};
use sqlx::{
    Connection, Decode, Encode, Row, Sqlite, Type,
    sqlite::{SqliteArgumentValue, SqliteConnection, SqliteTypeInfo},
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = key_id!("f0000000-0000-4000-8000-00000000000f");

/// The automatic columns' key source. No test in this binary installs the
/// global, so every column round trip here proves the column reads `K`.
struct TestKeys;

impl KeyContext for TestKeys {
    fn encryption_keys() -> Result<&'static dyn EncryptionKeyProvider, Error> {
        static KEYS: LazyLock<LocalEncryptionKeyring> = LazyLock::new(|| {
            LocalEncryptionKeyring::new(EncryptionKey::new(KEY_ID, [59; 32]), []).unwrap()
        });

        Ok(&*KEYS)
    }
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
    const ID: IndexId = index_id!("e0000000-0000-4000-8000-00000000000e");
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
    assert_sqlx_traits::<Encrypted<TestField, TestKeys>>();
    assert_sqlx_traits::<Ciphertext<TestField>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();

    let blob: SqliteTypeInfo = <Vec<u8> as Type<Sqlite>>::type_info();
    assert_eq!(
        <Encrypted<TestField, TestKeys> as Type<Sqlite>>::type_info(),
        blob
    );
    assert_eq!(<Ciphertext<TestField> as Type<Sqlite>>::type_info(), blob);
    assert_eq!(<BlindIndex<IndexSpec> as Type<Sqlite>>::type_info(), blob);
}

#[test]
fn sqlite_encode_encrypts_plaintext_into_an_owned_blob() {
    assert_sqlx_encode::<Encrypted<TestField, TestKeys>>();
    assert_sqlx_encode::<Ciphertext<TestField>>();
    assert_sqlx_encode::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    let value = Encrypted::<TestField, TestKeys>::new("mark@example.com".to_owned());
    let mut buffer = Vec::new();

    let result =
        <Encrypted<TestField, TestKeys> as Encode<'_, Sqlite>>::encode_by_ref(&value, &mut buffer)
            .unwrap();

    assert!(!result.is_null());
    assert!(only_blob(&buffer).starts_with(b"CBX\0"));
}

#[test]
fn sqlite_ciphertext_encoding_preserves_the_binary_envelope() {
    let keys = TestKeys::encryption_keys().unwrap();
    let bytes = encrypt(TestField::ID, TestField::PADDING, b"value", keys).unwrap();
    let ciphertext = Ciphertext::<TestField>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = Vec::new();

    let result =
        <Ciphertext<TestField> as Encode<'_, Sqlite>>::encode_by_ref(&ciphertext, &mut buffer)
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

        let value = Encrypted::<TestField, TestKeys>::new("mark@example.com".to_owned());
        sqlx::query("INSERT INTO secrets (value) VALUES (?)")
            .bind(&value)
            .execute(&mut connection)
            .await
            .unwrap();

        let row = sqlx::query("SELECT value FROM secrets")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let ciphertext: Ciphertext<TestField> = row.try_get("value").unwrap();
        let decrypted: Encrypted<TestField, TestKeys> = row.try_get("value").unwrap();

        assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
        assert_eq!(decrypted.expose_secret(), "mark@example.com");
        // The column used `TestKeys`; the global was never installed.
        assert_eq!(
            ciphertext
                .decrypt_with(TestKeys::encryption_keys().unwrap())
                .unwrap()
                .expose_secret(),
            "mark@example.com"
        );
        assert_eq!(keys::installed().unwrap_err(), Error::KeysNotInstalled);
    });
}

#[test]
fn sqlite_binds_an_explicitly_decrypted_value_through_its_own_key_context() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE secrets (value BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();

        let explicit = TestKeys::encryption_keys().unwrap();
        let stored = Encrypted::<TestField>::new("mark@example.com")
            .encrypt_with(explicit)
            .unwrap();
        let value = stored
            .decrypt_with(explicit)
            .unwrap()
            .with_key_context::<TestKeys>();

        sqlx::query("INSERT INTO secrets (value) VALUES (?)")
            .bind(&value)
            .execute(&mut connection)
            .await
            .unwrap();

        let row = sqlx::query("SELECT value FROM secrets")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let decrypted: Encrypted<TestField, TestKeys> = row.try_get("value").unwrap();

        assert_eq!(decrypted.expose_secret(), "mark@example.com");
        assert_eq!(keys::installed().unwrap_err(), Error::KeysNotInstalled);
    });
}

#[test]
fn sqlite_default_column_fails_closed_without_installed_keys() {
    let value = Encrypted::<TestField>::new("mark@example.com");
    let mut buffer = Vec::new();

    let Err(error) =
        <Encrypted<TestField> as Encode<'_, Sqlite>>::encode_by_ref(&value, &mut buffer)
    else {
        panic!("encoding without installed keys must fail");
    };

    assert_eq!(
        error.downcast_ref::<Error>(),
        Some(&Error::KeysNotInstalled)
    );
    assert!(buffer.is_empty());
}
