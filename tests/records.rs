//! Public-boundary tests for records: whole rows sealed and opened under one binding.

use cryptbox::{
    BlindIndex, BlindIndexError, BlindIndexKey, BlindIndexKeySource, BlindIndexKeyring,
    BlindIndexSpec, EncryptionKey, EncryptionKeySource, EncryptionKeyring, Error, IndexId, Keys,
    Padding, Record, Recorded, Seal, SealId, Sealed, Tenant, TenantId, Utf8,
};
use zeroize::Zeroizing;

/// A customer's email, bound to its tenant and record.
struct CustomerEmail;

impl Seal for CustomerEmail {
    const ID: SealId = cryptbox::seal_id!("6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Recorded<Tenant, i64>;
    type Indexes = (EmailLookup,);
}

/// A customer's note, bound to its tenant only.
struct CustomerNote;

impl Seal for CustomerNote {
    const ID: SealId = cryptbox::seal_id!("0d7e3a95-4b1c-4e62-8f0a-9c5b2d7e1f38");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Scope = Tenant;
    type Indexes = ();
}

/// A case-insensitive email lookup. One bit, so most rows are false candidates.
struct EmailLookup;

impl BlindIndexSpec for EmailLookup {
    type Seal = CustomerEmail;
    type Scope = Tenant;
    const ID: IndexId = cryptbox::index_id!("2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53");
    const BITS: u16 = 1;
    const NORMALIZER: &'static str = "email/1";
    type Query = str;

    fn normalize_query(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Ok(Zeroizing::new(
            query.trim().to_ascii_lowercase().into_bytes(),
        ))
    }

    fn normalize_value(value: &String) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        Self::normalize_query(value)
    }
}

/// A hand-written record, as `#[derive(Record)]` documents its expansion.
#[derive(Clone, Debug, PartialEq)]
struct Customer {
    id: i64,
    email: String,
    note: String,
}

struct SealedCustomer {
    id: i64,
    email: Sealed<CustomerEmail>,
    email_lookup: BlindIndex<EmailLookup>,
    note: Sealed<CustomerNote>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // The derive's sealers take the record ID by reference.
impl Customer {
    fn seal_email<K>(
        value: &String,
        binding: &Tenant,
        record: &i64,
        keys: &K,
    ) -> Result<(Sealed<CustomerEmail>, BlindIndex<EmailLookup>), Error>
    where
        K: EncryptionKeySource + BlindIndexKeySource + ?Sized,
    {
        let prepared = Sealed::<CustomerEmail>::prepare(value, (binding, record), keys)?
            .with_index_with::<EmailLookup>(keys)?;
        let email_lookup = prepared.index::<EmailLookup>()?.to_blind_index();

        Ok((prepared.into_sealed(), email_lookup))
    }

    fn seal_note<K>(
        value: &String,
        binding: &Tenant,
        _record: &i64,
        keys: &K,
    ) -> Result<Sealed<CustomerNote>, Error>
    where
        K: EncryptionKeySource + ?Sized,
    {
        Sealed::<CustomerNote>::seal(value, binding, keys)
    }
}

impl Record for Customer {
    type Sealed = SealedCustomer;
    type Scope = Tenant;

    fn seal<K>(&self, binding: &Tenant, keys: &K) -> Result<SealedCustomer, Error>
    where
        K: EncryptionKeySource + BlindIndexKeySource + ?Sized,
    {
        let (email, email_lookup) = Self::seal_email(&self.email, binding, &self.id, keys)?;
        let note = Self::seal_note(&self.note, binding, &self.id, keys)?;

        Ok(SealedCustomer {
            id: self.id,
            email,
            email_lookup,
            note,
        })
    }

    fn open<K>(sealed: SealedCustomer, binding: &Tenant, keys: &K) -> Result<Self, Error>
    where
        K: EncryptionKeySource + ?Sized,
    {
        let email = sealed.email.open((binding, &sealed.id), keys)?;
        let note = sealed.note.open(binding, keys)?;

        Ok(Self {
            id: sealed.id,
            email,
            note,
        })
    }
}

impl cryptbox::IndexedBy<EmailLookup> for Customer {
    fn indexed_value(&self) -> &String {
        &self.email
    }
}

// Fixed index keys keep the false candidates of the one-bit index deterministic.
fn keys() -> Keys {
    let encryption = EncryptionKey::new(
        cryptbox::key_id!("50000000-0000-4000-8000-000000000005"),
        [0x42; 32],
    );
    let blind_indexes = BlindIndexKey::new(
        cryptbox::index_key_id!("70000000-0000-4000-8000-000000000007"),
        [0x24; 32],
    );

    Keys::new(EncryptionKeyring::new(encryption, []).unwrap())
        .with_blind_indexes(BlindIndexKeyring::new(blind_indexes, []).unwrap())
}

fn tenant(name: &[u8]) -> Tenant {
    Tenant(TenantId::new(name.to_vec()).unwrap())
}

fn customer(id: i64, email: &str) -> Customer {
    Customer {
        id,
        email: email.to_owned(),
        note: format!("note {id}"),
    }
}

#[test]
fn a_record_round_trips_under_its_binding() {
    let keys = keys();
    let acme = tenant(b"acme");
    let ada = customer(7, "ada@example.com");

    let sealed = ada.seal(&acme, &keys).unwrap();

    assert_eq!(Customer::open(sealed, &acme, &keys).unwrap(), ada);
}

#[test]
fn a_seal_that_binds_the_record_cannot_move_to_another_record() {
    let keys = keys();
    let acme = tenant(b"acme");
    let ada = customer(7, "ada@example.com").seal(&acme, &keys).unwrap();
    let mut bob = customer(8, "bob@example.com").seal(&acme, &keys).unwrap();

    bob.email = ada.email;

    assert_eq!(
        Customer::open(bob, &acme, &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn a_seal_that_binds_no_record_is_bound_to_the_binding_alone() {
    let keys = keys();
    let acme = tenant(b"acme");
    let ada = customer(7, "ada@example.com").seal(&acme, &keys).unwrap();

    assert_eq!(ada.note.open(&acme, &keys).unwrap(), "note 7");
    assert_eq!(
        Customer::open(ada, &tenant(b"globex"), &keys).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn open_matching_drops_false_candidates() {
    let keys = keys();
    let acme = tenant(b"acme");
    let emails = [
        "ada@example.com",
        "bob@example.com",
        " ADA@example.com",
        "carol@example.com",
        "dave@example.com",
        "erin@example.com",
        "frank@example.com",
        "grace@example.com",
    ];
    let rows = (0..)
        .zip(emails)
        .map(|(id, email)| customer(id, email).seal(&acme, &keys).unwrap());

    // What a store returns for the probes: every row whose stored index matches one.
    let probes = EmailLookup::probes_with("ada@example.com", &acme, &keys).unwrap();
    let candidates: Vec<_> = rows
        .filter(|row| probes.contains(&row.email_lookup))
        .collect();
    let candidate_ids: Vec<_> = candidates.iter().map(|row| row.id).collect();
    // One index bit leaves about half of the other rows as false candidates.
    assert!(
        candidate_ids.len() > 2,
        "no false candidates: {candidate_ids:?}"
    );

    let matches = cryptbox::open_matching::<Customer, EmailLookup>(
        candidates,
        "ada@example.com",
        &acme,
        &keys,
    )
    .unwrap();

    assert_eq!(
        matches,
        [
            customer(0, "ada@example.com"),
            customer(2, " ADA@example.com")
        ]
    );
}

#[cfg(feature = "derive")]
mod derived {
    use super::{
        BlindIndexSpec, Customer, CustomerEmail, CustomerNote, EmailLookup, Record, SealedCustomer,
        keys, tenant,
    };

    /// The derived equivalent of [`Customer`].
    #[derive(Clone, Debug, PartialEq, cryptbox::Record)]
    #[cryptbox(record_id = id, sealed = SealedDerivedCustomer)]
    struct DerivedCustomer {
        #[cryptbox(plaintext)]
        id: i64,
        #[cryptbox(seal = CustomerEmail, index(EmailLookup as email_lookup))]
        email: String,
        #[cryptbox(seal = CustomerNote)]
        note: String,
    }

    fn derived(id: i64, email: &str) -> DerivedCustomer {
        DerivedCustomer {
            id,
            email: email.to_owned(),
            note: format!("note {id}"),
        }
    }

    #[test]
    fn a_derived_record_opens_rows_of_its_hand_written_equivalent() {
        let keys = keys();
        let acme = tenant(b"acme");
        let manual = super::customer(7, "ada@example.com")
            .seal(&acme, &keys)
            .unwrap();

        let sealed = SealedDerivedCustomer {
            id: manual.id,
            email: manual.email,
            email_lookup: manual.email_lookup,
            note: manual.note,
        };

        assert_eq!(
            DerivedCustomer::open(sealed, &acme, &keys).unwrap(),
            derived(7, "ada@example.com")
        );
    }

    #[test]
    fn a_hand_written_record_opens_rows_of_its_derived_equivalent() {
        let keys = keys();
        let acme = tenant(b"acme");
        let derived = derived(7, "ada@example.com").seal(&acme, &keys).unwrap();
        // Blind indexes are deterministic: both write the same one.
        let manual = super::customer(7, "ada@example.com")
            .seal(&acme, &keys)
            .unwrap();
        assert_eq!(derived.email_lookup, manual.email_lookup);

        let sealed = SealedCustomer {
            id: derived.id,
            email: derived.email,
            email_lookup: derived.email_lookup,
            note: derived.note,
        };

        assert_eq!(
            Customer::open(sealed, &acme, &keys).unwrap(),
            super::customer(7, "ada@example.com")
        );
    }

    #[test]
    fn a_field_sealer_seals_one_field_with_its_indexes_for_a_partial_update() {
        let keys = keys();
        let acme = tenant(b"acme");
        let row = derived(7, "ada@example.com").seal(&acme, &keys).unwrap();

        let (email, email_lookup) =
            DerivedCustomer::seal_email(&"ada@example.org".to_owned(), &acme, &7, &keys).unwrap();
        let note = DerivedCustomer::seal_note(&"updated".to_owned(), &acme, &7, &keys).unwrap();

        let updated = SealedDerivedCustomer {
            email,
            email_lookup,
            note,
            ..row
        };
        let probes = EmailLookup::probes_with("ada@example.org", &acme, &keys).unwrap();
        assert!(probes.contains(&updated.email_lookup));
        assert_eq!(
            updated.email.open((&acme, &7_i64), &keys).unwrap(),
            "ada@example.org"
        );
        assert_eq!(
            DerivedCustomer::open(updated, &acme, &keys).unwrap(),
            DerivedCustomer {
                id: 7,
                email: "ada@example.org".to_owned(),
                note: "updated".to_owned(),
            }
        );
    }

    #[test]
    fn open_matching_finds_derived_records() {
        let keys = keys();
        let acme = tenant(b"acme");
        let rows = [
            derived(0, "ada@example.com").seal(&acme, &keys).unwrap(),
            derived(1, "bob@example.com").seal(&acme, &keys).unwrap(),
        ];

        let matches = cryptbox::open_matching::<DerivedCustomer, EmailLookup>(
            rows,
            "ADA@example.com",
            &acme,
            &keys,
        )
        .unwrap();

        assert_eq!(matches, [derived(0, "ada@example.com")]);
    }
}

#[cfg(feature = "derive")]
mod own_seals {
    use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Record, Seal, Sealed, Tenant};
    use zeroize::Zeroizing;

    use super::{
        Customer, CustomerEmail, CustomerNote, EmailLookup, SealedCustomer, customer, keys, tenant,
    };

    /// [`Customer`] with its email's seal declared on the field: the same ID,
    /// scope, and record binding as [`CustomerEmail`], so the same bytes.
    #[derive(Clone, Debug, PartialEq, cryptbox::Record)]
    #[cryptbox(record_id = id, sealed = SealedInlineCustomer)]
    pub struct InlineCustomer {
        #[cryptbox(plaintext)]
        id: i64,
        #[cryptbox(
            id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
            scope = Tenant,
            index(InlineEmailLookup as email_lookup),
        )]
        email: String,
        #[cryptbox(seal = CustomerNote)]
        note: String,
    }

    fn normalize_email(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        EmailLookup::normalize_query(query)
    }

    /// [`EmailLookup`] over the field's own seal.
    #[derive(cryptbox::BlindIndexSpec)]
    #[cryptbox(
        id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
        seal = InlineCustomerEmail,
        bits = 1,
        query = str,
        normalize = normalize_email,
        normalizer = "email/1",
    )]
    struct InlineEmailLookup;

    /// A field seal under another name.
    #[derive(Debug, PartialEq, cryptbox::Record)]
    #[cryptbox(record_id = id, sealed = SealedRenamed)]
    struct Renamed {
        #[cryptbox(plaintext)]
        id: i64,
        #[cryptbox(id = "5b7d9f13-2c4e-4a68-8b0d-1f3e5a7c9b24", name = RenamedNickname)]
        nickname: String,
    }

    #[test]
    fn a_field_seal_is_named_after_its_record_and_field() {
        assert_eq!(InlineCustomerEmail::ID, CustomerEmail::ID);
        assert_eq!(
            RenamedNickname::ID,
            cryptbox::seal_id!("5b7d9f13-2c4e-4a68-8b0d-1f3e5a7c9b24")
        );
    }

    #[test]
    fn a_field_seal_writes_the_bytes_of_its_hand_written_equivalent() {
        let keys = keys();
        let acme = tenant(b"acme");
        let inline = InlineCustomer {
            id: 7,
            email: "ada@example.com".to_owned(),
            note: "note 7".to_owned(),
        };
        let row = inline.seal(&acme, &keys).unwrap();
        let manual = customer(7, "ada@example.com").seal(&acme, &keys).unwrap();
        // Blind indexes are deterministic: both write the same one.
        assert_eq!(row.email_lookup.as_bytes(), manual.email_lookup.as_bytes());

        let sealed = SealedCustomer {
            id: row.id,
            email: Sealed::from_bytes(row.email.into_bytes()).unwrap(),
            email_lookup: BlindIndex::from_bytes(row.email_lookup.into_bytes()).unwrap(),
            note: row.note,
        };
        assert_eq!(
            Customer::open(sealed, &acme, &keys).unwrap(),
            customer(7, "ada@example.com")
        );
    }

    #[test]
    fn a_field_seal_is_bound_to_its_record() {
        let keys = keys();
        let acme = tenant(b"acme");
        let (email, _) =
            InlineCustomer::seal_email(&"ada@example.com".to_owned(), &acme, &7, &keys).unwrap();

        assert_eq!(email.open((&acme, &7), &keys).unwrap(), "ada@example.com");
        assert_eq!(
            email.open((&acme, &8), &keys).unwrap_err(),
            cryptbox::Error::AuthenticationFailed
        );
        let renamed = Renamed {
            id: 1,
            nickname: "ada".to_owned(),
        };
        let row = renamed.seal(&(), &keys).unwrap();
        assert_eq!(row.nickname.open(((), &1), &keys).unwrap(), "ada");
    }
}

#[cfg(feature = "derive")]
mod self_valued {
    use cryptbox::{BlindIndex, BlindIndexError, BlindIndexSpec, Record, Tenant};
    use zeroize::Zeroizing;

    use super::{Customer, CustomerNote, EmailLookup, SealedCustomer, customer, keys, tenant};

    /// [`super::CustomerEmail`] as its own value: the same ID, bytes, and index.
    #[derive(Clone, Debug, PartialEq, cryptbox::Seal)]
    #[cryptbox(
        id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
        transparent,
        scope = cryptbox::Recorded<Tenant, i64>,
        indexes(OwnEmailLookup),
    )]
    struct OwnEmail(String);

    impl OwnEmail {
        fn as_str(&self) -> &str {
            &self.0
        }
    }

    fn normalize_email(query: &str) -> Result<Zeroizing<Vec<u8>>, BlindIndexError> {
        EmailLookup::normalize_query(query)
    }

    /// [`EmailLookup`] over [`OwnEmail`].
    #[derive(cryptbox::BlindIndexSpec)]
    #[cryptbox(
        id = "2e4c7b1a-5d3f-4a86-9b20-7f1e6c8d4a53",
        seal = OwnEmail,
        bits = 1,
        query = str,
        normalize = normalize_email,
        normalizer = "email/1",
        project = OwnEmail::as_str,
    )]
    struct OwnEmailLookup;

    /// [`Customer`] with a field whose type is its own seal.
    #[derive(Clone, Debug, PartialEq, cryptbox::Record)]
    #[cryptbox(record_id = id, sealed = SealedOwnCustomer)]
    struct OwnCustomer {
        #[cryptbox(plaintext)]
        id: i64,
        #[cryptbox(seal, index(OwnEmailLookup as email_lookup))]
        email: OwnEmail,
        #[cryptbox(seal = CustomerNote)]
        note: String,
    }

    #[test]
    fn a_field_sealed_as_its_own_type_reads_as_its_marker_equivalent() {
        let keys = keys();
        let acme = tenant(b"acme");
        let own = OwnCustomer {
            id: 7,
            email: OwnEmail("ada@example.com".to_owned()),
            note: "note 7".to_owned(),
        };
        let row = own.seal(&acme, &keys).unwrap();
        let manual = customer(7, "ada@example.com").seal(&acme, &keys).unwrap();
        // Blind indexes are deterministic: both write the same one.
        assert_eq!(row.email_lookup.as_bytes(), manual.email_lookup.as_bytes());

        let sealed = SealedCustomer {
            id: row.id,
            email: cryptbox::Sealed::from_bytes(row.email.into_bytes()).unwrap(),
            email_lookup: BlindIndex::from_bytes(row.email_lookup.into_bytes()).unwrap(),
            note: row.note,
        };

        assert_eq!(
            Customer::open(sealed, &acme, &keys).unwrap(),
            customer(7, "ada@example.com")
        );
    }
}

#[cfg(all(feature = "derive", feature = "sqlx-sqlite"))]
mod sqlite {
    use sqlx::{Connection, sqlite::SqliteConnection};

    use super::{CustomerEmail, CustomerNote, EmailLookup, Record, keys, tenant};

    /// A record whose sealed struct is read with `sqlx::FromRow`.
    #[derive(Debug, PartialEq, cryptbox::Record)]
    #[cryptbox(record_id = id, sealed = SealedStoredCustomer, attr(derive(sqlx::FromRow)))]
    #[sqlx(rename_all = "UPPERCASE")]
    struct StoredCustomer {
        #[cryptbox(plaintext)]
        id: i64,
        #[cryptbox(seal = CustomerEmail, index(EmailLookup as email_lookup))]
        #[sqlx(rename = "EMAIL_CIPHERTEXT")]
        email: String,
        #[cryptbox(seal = CustomerNote)]
        note: String,
    }

    #[test]
    fn a_sealed_struct_reads_rows_with_forwarded_sqlx_attributes() {
        let keys = keys();
        let acme = tenant(b"acme");
        let ada = StoredCustomer {
            id: 7,
            email: "ada@example.com".to_owned(),
            note: "VIP".to_owned(),
        };
        let sealed = ada.seal(&acme, &keys).unwrap();

        let stored = futures_executor::block_on(async {
            let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
            sqlx::query(
                "CREATE TABLE customers \
                 (ID INTEGER, EMAIL_CIPHERTEXT BLOB, EMAIL_LOOKUP BLOB, NOTE BLOB)",
            )
            .execute(&mut connection)
            .await
            .unwrap();
            sqlx::query("INSERT INTO customers VALUES (?, ?, ?, ?)")
                .bind(sealed.id)
                .bind(&sealed.email)
                .bind(&sealed.email_lookup)
                .bind(&sealed.note)
                .execute(&mut connection)
                .await
                .unwrap();

            sqlx::query_as::<_, SealedStoredCustomer>("SELECT * FROM customers")
                .fetch_one(&mut connection)
                .await
                .unwrap()
        });

        assert_eq!(StoredCustomer::open(stored, &acme, &keys).unwrap(), ada);
    }
}
