//! Public-boundary tests for the optional `SQLx` `SQLite` adapter.

#![cfg(feature = "sqlx-sqlite")]

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexSpec, EncryptionKey, EncryptionKeyring, IndexId, KeyId,
    Keys, Padding, Seal, Sealed, Utf8, index_id, key_id,
};
use sqlx::{
    Connection, Decode, Encode, Row, Sqlite, Type,
    sqlite::{SqliteArgumentValue, SqliteConnection, SqliteTypeInfo},
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = key_id!("f0000000-0000-4000-8000-00000000000f");

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

fn only_blob<'a>(buffer: &'a [SqliteArgumentValue<'_>]) -> &'a [u8] {
    let [SqliteArgumentValue::Blob(bytes)] = buffer else {
        panic!("expected exactly one SQLite BLOB argument");
    };
    bytes
}

#[test]
fn encrypted_storage_types_map_to_sqlite_blob() {
    assert_sqlx_traits::<Sealed<TestSeal>>();
    assert_sqlx_traits::<BlindIndex<IndexSpec>>();

    let blob: SqliteTypeInfo = <Vec<u8> as Type<Sqlite>>::type_info();
    assert_eq!(<Sealed<TestSeal> as Type<Sqlite>>::type_info(), blob);
    assert_eq!(<BlindIndex<IndexSpec> as Type<Sqlite>>::type_info(), blob);
}

#[test]
fn sqlite_sealed_encoding_preserves_the_binary_envelope() {
    let keys = test_keys();
    let bytes = Sealed::<TestSeal>::seal(&"value".to_owned(), &keys)
        .unwrap()
        .into_bytes();
    let ciphertext = Sealed::<TestSeal>::from_bytes(bytes.clone()).unwrap();
    let mut buffer = Vec::new();

    let result =
        <Sealed<TestSeal> as Encode<'_, Sqlite>>::encode_by_ref(&ciphertext, &mut buffer).unwrap();

    assert!(!result.is_null());
    assert_eq!(only_blob(&buffer), bytes);
}

#[test]
fn sqlite_round_trips_sealed_values() {
    futures_executor::block_on(async {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE secrets (value BLOB NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();

        let keys = test_keys();
        let value = Sealed::<TestSeal>::seal(&"mark@example.com".to_owned(), &keys).unwrap();
        sqlx::query("INSERT INTO secrets (value) VALUES (?)")
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
