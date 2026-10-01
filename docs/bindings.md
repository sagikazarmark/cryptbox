# Bind values to their seal and record

A binding is the cryptographic domain of a value: the seal it is sealed with,
and, for a field of a record, the record's ID. A value opens only under the same
binding, so it cannot be moved to another seal, field, or row. Tenants, orgs,
and workspaces are kept apart by keys, not by the binding. This page explains
what a value is bound to, where its record ID comes from, and how blind indexes
and tenants fit in.
[Documentation](README.md) · [Choosing keyrings](choosing-keyrings.md).

Start from [seal your first value](first-field.md), whose seal binds values to
its seal ID alone. Bind values to their record when a value copied between rows
must fail to open, and give each tenant its own keyring when tenants must not be
able to read each other's values: see [choosing keyrings](choosing-keyrings.md).

## Declarations are schema, values are arguments

A binding has two halves, and they change on different schedules:

| Half | Where it is declared | When it changes |
| --- | --- | --- |
| **Declaration**: whether a record is bound, and its ID's kind | The seal's `Record`, or a record's `record_id` field | Only through a [declaration migration](#change-a-binding-declaration) |
| **Values**: this record | The binding arguments of each call, or the row | Every call |

One seal never seals with different declarations on different calls: that would
give one value two valid encodings. The declaration is persistent schema exactly
as a seal ID or codec is, and every envelope carries a fingerprint of it, so a
reader that expects another declaration reports `Error::BindingMismatch` instead
of an authentication failure.

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
`Sealed<CustomerEmail>` and a `BlindIndex` column per index, and a seal for each
sealed field, named after the record and the field. `customer.seal(&keys)` seals
the whole row, and `Customer::open(stored, &keys)` opens it, with the keys of
the org the row belongs to.

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
add the check the binding does not: with a keyring per org, another org's row
fails to open with `UnknownEncryptionKey`, and so does a row whose org column
was edited to name another org, since the application then picks that org's
keys. Under one shared keyring, an edited org column goes unnoticed. Storage can
also return a whole authentic row in place of another, which no binding
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
  (`PartType`). Changing its type is a declaration change.

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

A value that is not a row, such as a message or a cache entry, is sealed with a
seal of its own, which names whether it binds a record:

```rust
#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    record = Uuid,
)]
pub struct InvoiceNote;

let sealed = Sealed::<InvoiceNote>::seal(&note, &invoice_id, &keys)?;
let note = sealed.open(&invoice_id, &keys)?;
```

The binding arguments of a call are typed by the seal
([`Args<F>`](https://docs.rs/cryptbox/latest/cryptbox/trait.Args.html)): `()`,
or `&id` for a seal that binds a record. A missing or extra record is a type
error rather than a failed read.

The [tenant example](../examples/tenant_field.rs) is a complete program: a
seal bound to a record, one `EncryptionKeyring` per tenant, and assertions that
another record fails authentication while another tenant's keyring reports
`UnknownEncryptionKey`. Run it from a checkout, and expect
`Record-bound round trip with a keyring per tenant succeeded.`:

```sh
cargo run --locked --example tenant_field
```

## Move a record between orgs

The binding does not name the org, so moving a row to another org that shares
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

## Change a binding declaration

Binding a value into a record, or out of one, is a migration, not a deployment.
On a record field, `legacy(…)` names the declaration it had before: its seal ID
(by default the current one) and whether it bound the record ID (by default
yes). Rows sealed with it keep opening, `Record::seal` writes the new
declaration, and a [sweep](reencryption-sweep.md#binding-declaration-changes)
reseals the rest. Rows of the old declaration are recognized by the fingerprint
in their header. Close the window, by deleting `legacy(…)`, only after a
complete verification pass counts no legacy-binding rows; the schema manifest
lists open windows.

Changing the record ID's kind is outside that window: those values must be
resealed under an explicitly planned path of your own.

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

`assert_unique_ids!` rejects seal and index IDs shared by listed markers, and a
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
- [Wire format](wire-format.md#binding): the exact binding bytes and the
  binding fingerprint.
- [Glossary](glossary.md): binding, record, stored form, index handle.
