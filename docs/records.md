# Records

Every sealed value is sealed under a context: its seal ID, and, for a field of a
record, the record's ID. A value opens only under the same context, so a
standalone value cannot be moved to another seal, and a record's field cannot be
moved to another seal, field, or row. Tenants, orgs, and workspaces are kept
apart by keys, not by the context. This page explains records, where their
record IDs come from, and how blind indexes and tenants fit in.
[Documentation](README.md) · [Choosing keyrings](choosing-keyrings.md).

Start from [seal your first value](first-field.md), whose values are standalone:
sealed under their seal ID alone. Make values fields of a record when a value copied
between rows must fail to open, and give each tenant its own keyring when tenants
must not be able to read each other's values: see
[choosing keyrings](choosing-keyrings.md).

## Records bind their sealed fields to their ID

A row stores its record ID as a column, so a record declares it as a field.
Every field has one role, and a field without one fails the build, so nothing is
stored as it is by accident:

```rust
#[derive(cryptbox::Record)]
pub struct Customer {
    #[cryptbox(record_id)]
    pub id: Uuid,
    #[cryptbox(plaintext)]
    pub org: OrgId,
    #[cryptbox(plaintext)]
    pub workspace: WorkspaceId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        bits = 32,
        normalize = normalize_email,
        normalizer = "email/1",
    ))]
    pub email: String,
    #[cryptbox(seal = "5d1f0c3a-8f6e-4b1d-9a7c-2e4b6d8f0a13")]
    pub note: Option<String>,
    #[cryptbox(plaintext)]
    pub created_at: i64,
}
```

Every sealed field is bound to its own seal and to the record ID. The derive
generates the stored form, `StoredCustomer`, with each sealed field as its
`Sealed<CustomerEmail, InRecord<Uuid>>` and a `BlindIndex` column per index, and
a seal for each sealed field, named after the record and the field. `customer.seal(&keys)` seals
the whole row, and `Customer::open(stored, &keys)` opens it, with the keys of
the org the row belongs to.

A seal knows nothing of the record: the record is a context its seals' values
are sealed in, `InRecord<Uuid>`, the second parameter of `Sealed`. The derive
seals each field with `Sealed::seal_in` under the record ID, and opens it with
`Sealed::open_in` under the ID the row stores. Call `open_in` yourself to read
one field of a stored row:

```rust
let email = stored.email.open_in(&stored.id, &keys)?;
```

## Plaintext columns are authorized, not authenticated

Opening a row reads its record ID from the row and authenticates it: a sealed
value copied from another row, or from another field, fails to open. Its other
columns, such as its org and workspace, are plaintext and are not authenticated.
They say where the row belongs; authorize on them like any other column:

```rust
let customer = Customer::open(stored, &keys)?;
authz.require(user, customer.org, customer.workspace)?;
```

or check them before anything is decrypted:

```rust
let customer = Customer::open_expecting(stored, &keys, |row| row.org == org)?;
```

`open_expecting` reports `Error::UnexpectedRecord` for a row it rejects. Keys
add the check the context does not: with a keyring per org, another org's row
fails to open with `UnknownEncryptionKey`, and so does a row whose org column
was edited to name another org, since the application then picks that org's
keys. Under one shared keyring, an edited org column goes unnoticed. Storage can
also return a whole authentic row in place of another, which no context
prevents: when you asked for one record, check its ID, as `open_expecting` does.

## Record IDs

Every sealed field of a record is bound to its record ID, so the ID must exist
before the first value is sealed:

- **The client generates it**, UUIDv7 recommended, so that inserts carry their
  ID. Sealing after an insert, against a database-assigned key, is not
  supported.
- **It need not be the primary key.** A row can keep its own surrogate key and
  carry a separate, stable record ID; what matters is that the ID never changes
  while sealed values exist.
- **It is never encrypted**, because opening the row needs it first.
- **Its kind is fixed**: a UUID, an `i64`, or bytes, the kind of its type
  (`[u8; 16]` or `uuid::Uuid`, `i64`, or `Vec<u8>`). Changing its type is a
  declaration change. Store an ID newtype's inner value in the record.

## Blind indexes

A blind index is declared on its field and derived under its seal ID alone,
never the record ID, which a query cannot know. A lookup derives probes, selects
candidate rows within what the caller may read, and opens them:

```rust
let probes = Customer::EMAIL_INDEX.probes("ada@example.com", &keys)?;
let rows: Vec<StoredCustomer> = select_by_email_index(org, &probes)?; // WHERE org = ? AND email_index IN (…)

for hit in Customer::EMAIL_INDEX.open_matching("ada@example.com", rows, &keys)? {
    let customer = hit?;
    authz.require(user, customer.org, customer.workspace)?;
}
```

The handle, a const named after the index column, takes the query and the keys.
`open_matching` returns one result per candidate it keeps: it opens each row and
compares its value with the query, so the false candidates of a truncated index
are dropped, and a row that fails to open is reported as its error, never as a
non-match.

Equal values of one seal derive equal index bytes under the same keys, so under
one shared blind-index keyring, equal emails in two orgs share index bytes.
Give each org its own blind-index keyring when that equality must not be
visible across orgs: equal values then derive unrelated bytes.

## Standalone values

A value that is not a row's field, such as a cache entry or a token, is sealed
with a seal of its own and bound to its seal ID alone:

```rust
#[derive(cryptbox::Seal)]
#[cryptbox(id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13", value = String)]
pub struct SessionNote;

let sealed = Sealed::<SessionNote>::seal(&note, &keys)?;
let note = sealed.open(&keys)?;
```

It binds no record, so a standalone value copied to another place that stores
the same seal still opens. When a value must stay with the thing it belongs to,
make it a field of a record: a record's stored form also works as a message,
with Serde's derives forwarded through `stored(…)`.

A seal knows nothing of where its values are stored, so `Sealed::seal` also
accepts a record field's seal. Its value is then standalone, `Sealed<F>`, and
fails to open as the record's with `Error::ContextMismatch`. Register each
context in the [schema manifest](testing.md) with `Manifest::sealed` and
`Manifest::record`: its `duplicates` reports a seal stored in several kinds of
context.

The [tenant example](../examples/tenant_field.rs) is a complete program: a
seal, one `EncryptionKeyring` per tenant, and assertions that another tenant's
keyring reports `UnknownEncryptionKey` and that a value moves to another tenant
only by an explicit reseal. Run it from a checkout, and expect
`Round trip with a keyring per tenant succeeded.`:

```sh
cargo run --locked --example tenant_field
```

## Move a record between orgs

The context does not name the org, so moving a row to another org that shares
its keys is a column update. With a keyring per org, the ciphertext is under the
old org's keys: open the record and seal it again with the new org's keys, or,
for a standalone value, `Sealed::reseal_across` opens with the old keys and
reseals with the new ones:

- **Every blind index of the moved value must be derived again** when the orgs
  have separate blind-index keys. `Record::seal` derives them; write the sealed
  fields and indexes in one atomic write.
- **A move to another org's keys crosses custody.** The value leaves the reach
  of the old org's keys, so it will survive that org being
  [shredded](shredding.md). Where residency or custody rules apply, treat the
  move as an export.
- **Nothing rewrites values in place by itself.** Reads never reseal, and a
  bounded [sweep](reencryption-sweep.md) is the tool for a whole population.

## Change a field's seal or record ID

A field's seal ID and its record ID's type are persistent schema. Changing
either, or moving a standalone value into a record, makes existing values fail to
open: under another seal ID with `Error::AuthenticationFailed`, and under
another declaration with `Error::ContextMismatch`. CryptBox has
no migration window for these changes yet; plan one of your own, such as reading
old rows with the old declaration while a job reseals them.

## ID hygiene

Seal IDs and index IDs are generated UUIDs, never derived from a Rust type name
and never copied from documentation:

```sh
uuidgen
```

Either case parses; these pages use the lowercase form. Generate one ID per
seal and index, and keep it unchanged for the life of the data: renaming a Rust
type does not change an ID, and reusing an ID makes two things one. Two examples
in this repository share an ID only where they mean one seal, as the SQLite and
searchable examples share the tutorial's `UserEmail`; a `UserEmail` marker in
another example is a different seal with its own ID, because the Rust name is
not the identity.

`#[derive(Record)]` rejects a seal or index ID repeated within one record,
`assert_unique_ids!` rejects seal and index IDs shared by listed markers, the
[manifest](integration.md#guarding-the-schema-in-ci) reports a seal ID shared
by fields of several records, and a
[manifest snapshot](integration.md#guarding-the-schema-in-ci) makes any change
to the IDs you have chosen a reviewable diff.

Key IDs follow separate rules, in [choosing keyrings](choosing-keyrings.md).

## What to read next

- [Choosing keyrings](choosing-keyrings.md): keeping tenants apart, custody,
  and testing the choice.
- [Shredding a tenant](shredding.md): what destroying a tenant's keys does and
  does not remove.
- [Integration design](integration.md): persistent schema, storage boundaries,
  search, and ORMs.
- [Wire format](wire-format.md#seal-context): the exact context bytes and the
  context fingerprint.
- [Glossary](glossary.md): context, record, stored form, index handle.
