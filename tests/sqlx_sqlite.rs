//! Public-boundary tests for the optional `SQLx` `SQLite` adapter.

#![cfg(feature = "sqlx-sqlite")]

use std::sync::Once;

use cryptbox::{
    BlindIndex, BlindIndexMetadata, BlindIndexRef, Ciphertext, Encrypted, EncryptionKey,
    EncryptionKeyProvider, Field, GlobalKeyContext, GlobalProviders, IndexId, KeyContext, KeyId,
    LocalEncryptionKeyring, Padding, Utf8, encrypt, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Row, Sqlite, Type,
    sqlite::{SqliteArgumentValue, SqliteConnection, SqliteTypeInfo},
};

const KEY_ID: KeyId = key_id!("f0000000-0000-4000-8000-00000000000f");

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
    assert_sqlx_traits::<Encrypted<TestField>>();
    assert_sqlx_traits::<Ciphertext<TestField>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();

    let blob: SqliteTypeInfo = <Vec<u8> as Type<Sqlite>>::type_info();
    assert_eq!(<Encrypted<TestField> as Type<Sqlite>>::type_info(), blob);
    assert_eq!(<Ciphertext<TestField> as Type<Sqlite>>::type_info(), blob);
    assert_eq!(<BlindIndex<IndexSpec> as Type<Sqlite>>::type_info(), blob);
}

#[test]
fn sqlite_encode_encrypts_plaintext_into_an_owned_blob() {
    install_keys();
    assert_sqlx_encode::<Encrypted<TestField>>();
    assert_sqlx_encode::<Ciphertext<TestField>>();
    assert_sqlx_encode::<BlindIndex<IndexSpec>>();
    assert_sqlx_encode::<BlindIndexRef<'static, IndexSpec>>();

    let value = Encrypted::<TestField>::new("mark@example.com".to_owned());
    let mut buffer = Vec::new();

    let result =
        <Encrypted<TestField> as Encode<'_, Sqlite>>::encode_by_ref(&value, &mut buffer).unwrap();

    assert!(!result.is_null());
    assert!(only_blob(&buffer).starts_with(b"CBX\0"));
}

#[test]
fn sqlite_ciphertext_encoding_preserves_the_binary_envelope() {
    let keys = install_keys();
    let bytes = encrypt(TestField::ID, b"value", keys).unwrap();
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
    install_keys();
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE secrets (value BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();

        let value = Encrypted::<TestField>::new("mark@example.com".to_owned());
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
        let decrypted: Encrypted<TestField> = row.try_get("value").unwrap();

        assert!(ciphertext.as_bytes().starts_with(b"CBX\0"));
        assert_eq!(decrypted.expose_secret(), "mark@example.com");
    });
}
