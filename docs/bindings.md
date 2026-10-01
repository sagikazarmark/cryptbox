# Bind values to what they belong to

A binding is the cryptographic domain of a value: the seal it is sealed with,
its **bound values**, such as the org and workspace it belongs to, and its
record when the seal binds one. A value opens only under the same binding, so
it cannot be moved to another org, workspace, row, or column. This page explains
how to declare bound values, where their values come from, and how blind
indexes are partitioned by them.
[Documentation](README.md) · [Choosing keyrings](choosing-keyrings.md).

Start from [seal your first value](first-field.md), whose seal binds values
to its seal ID alone. Add bound values when values of different tenants, orgs,
or residencies must not be interchangeable. Which keys protect them is a
separate choice: see [choosing keyrings](choosing-keyrings.md).

## Declarations are schema, values are arguments

A binding has two halves, and they change on different schedules:

| Half | Where it is declared | When it changes |
| --- | --- | --- |
| **Declaration**: the kinds of bound values and the record's kind | The seal's bound ID types and record, or a record's fields | Only through a [declaration migration](#change-a-binding-declaration) |
| **Values**: this org, this workspace, this record | The binding arguments of each call, or the row | Every call |

One seal never seals with different bound values on different calls: that
would give one value two valid encodings. The declaration is persistent schema
exactly as a seal ID or codec is, and every envelope carries a fingerprint of it,
so a reader that expects another declaration reports `Error::BindingMismatch`
instead of an authentication failure.

## Declare bound ID types

A bound value is one of the application's own ID types, marked with the kind of
value it is, once, on the type:

```rust
use uuid::Uuid;

#[derive(cryptbox::BoundId, Clone, Copy, PartialEq)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
pub struct OrgId(Uuid);

#[derive(cryptbox::BoundId, Clone, Copy, PartialEq)]
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
pub struct WorkspaceId(Uuid);
```

`kind` is a generated UUID, the part ID every value of the type is bound under,
whichever seal or record binds it: see [ID hygiene](#id-hygiene). The newtype
binds as its field, which holds a UUID (`uuid::Uuid` with the `uuid` feature, or
`[u8; 16]`), an `i64`, or bytes. `TenantId` is a ready-made bound ID of opaque
bytes.

## Records carry their bound values

A row stores the values it is bound to as its own columns, so a record
declares them as fields. Every field has one role, and a field without one
fails the build, so nothing is stored as it is by accident:

```rust
#[derive(cryptbox::Record)]
pub struct Customer {
    #[cryptbox(record_id)]
    pub id: Uuid,
    #[cryptbox(bound)]
    pub org: OrgId,
    #[cryptbox(bound)]
    pub workspace: WorkspaceId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(
        id = "ab78afa9-7aaa-499c-8239-037b7e136130",
        across(workspace),
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

Every sealed field is bound to its own seal, to all of the record's bound
values, and to its record ID. The derive generates the stored form,
`StoredCustomer`, with each sealed field as its `Sealed<CustomerEmail>` and a
`BlindIndex` column per index, and a seal for each sealed field, named after the
record and the field. `customer.seal(&keys)` seals the whole row, and
`Customer::open(stored, &keys)` opens it.

## Bound values are authenticated, then authorized

Opening a row reads its record ID and bound values from the row and
authenticates them: a row whose org column was changed, or whose sealed value
was copied from another row, fails to open. They say where the row belongs;
they do not say who may read it. Authorize on them:

```rust
let customer = Customer::open(stored, &keys)?;
authz.require(user, customer.org, customer.workspace)?;
```

or check them before anything is decrypted:

```rust
let customer = Customer::open_expecting(stored, &keys, |row| row.org == org)?;
```

`open_expecting` reports `Error::UnexpectedRecord` for a row it rejects. Keys add
a second check: with a keyring per org, another org's row fails to open with
`UnknownEncryptionKey`. Storage can still return a whole authentic row in place
of another, which no binding prevents: when you asked for one record, check its
ID, as `open_expecting` does.

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
- **Its kind is fixed**: a UUID, an `i64`, or bytes, the kind of its type.
  Changing its type is a declaration change.

## Partition each blind index

A blind index is declared on its field and partitioned by all of the record's
bound values, except those it spans, named with `across(…)`. Equal values in
different partitions derive unrelated index bytes; `across` widens the equality
the index reveals, visibly, in the declaration. A query supplies the partition's
values:

```rust
// The email index spans workspaces, so an org-wide search supplies the org.
let probes = Customer::EMAIL_INDEX.probes("ada@example.com", &org, &keys)?;
let rows: Vec<StoredCustomer> = select_by_email_index(org, &probes)?;

for hit in Customer::EMAIL_INDEX.open_matching("ada@example.com", &org, rows, &keys)? {
    let customer = hit?;
    // The workspace is read from the row and authenticated: authorize on it.
    authz.require(user, customer.org, customer.workspace)?;
}
```

The handle, a const named after the index column, takes its partition: the ID
type of the one bound value that partitions it, a generated struct with a field
per bound value for two or more, such as `CustomerNoteIndexPartition`, or `()`
for an index that spans them all. `open_matching` returns one result per
candidate it keeps: it opens each row and compares its value with the query, so
the false candidates of a truncated index are dropped, and it refuses a row of
another partition without decrypting it, as `Error::OutsidePartition`.

- **Partition by every value a query always knows**, such as the org, when
  equal values in different ones must not share index bytes.
- **Span a value a query does not know**, such as a workspace under an
  org-wide search. The record ID never partitions an index.
- **Two indexes over one field may partition differently.**
- **Changing a partition**, such as spanning another bound value, changes that
  index's bytes, as changing its normalizer does: look up with
  `migrate::probes_across` over both partitions while a
  [sweep](reencryption-sweep.md#blind-indexes) derives every stored index again.

## Standalone values

A value that is not a row, such as a message or a cache entry, is sealed with a
seal of its own, which names its bound ID types and whether it binds a record:

```rust
#[derive(cryptbox::Seal)]
#[cryptbox(
    id = "6c3b1f0e-8a24-4d5b-9e71-2f4a6c8d0b13",
    value = String,
    bound(OrgId),
    record = Uuid,
)]
pub struct InvoiceNote;

let sealed = Sealed::<InvoiceNote>::seal(&note, (&org, &invoice_id), &keys)?;
let note = sealed.open((&org, &invoice_id), &keys)?;
```

The binding arguments of a call are typed by the seal
([`Args<F>`](https://docs.rs/cryptbox/latest/cryptbox/trait.Args.html)): its
bound values in order, then its record ID: `()`, `&org`, `(&org, &workspace)`,
`(&org, &id)`. A missing or extra value is a type error rather than a failed
read. A standalone value's bound values come from the caller, never from the
value itself: take them from an authorized source, such as the request's
verified claims.

The [tenant example](../examples/tenant_field.rs) is a complete program: a
seal bound to a `TenantId` and a record, one `EncryptionKeyring` per tenant, and
assertions that another record of the same tenant fails authentication while
another tenant's keyring reports `UnknownEncryptionKey`. Run it from a checkout,
and expect `Tenant-bound round trip succeeded.`:

```sh
cargo run --locked --example tenant_field
```

## Move a record between orgs

Changing a bound value is not an update of a column: the ciphertext is bound to
the old values. Open the record, change the value, and seal it again, or, for a
standalone value, `Sealed::reseal_across` opens under the old binding and keys
and reseals under the new ones:

- **Every blind index of the moved value must be derived again**, because its
  partition includes the moved value. `Record::seal` derives them; write the
  sealed fields and indexes in one atomic write.
- **A move to another org's keys crosses custody.** The value leaves the reach
  of the old org's keys, so it will survive that org being
  [shredded](shredding.md). Where residency or custody rules apply, treat the
  move as an export.
- **Nothing rewrites values in place by itself.** Reads never reseal, and a
  bounded [sweep](reencryption-sweep.md) is the tool for a whole population.

## Change a binding declaration

Binding a value to another bound value, into a record, or out of one, is a
migration, not a deployment. On a record field, `legacy(…)` names the
declaration it had before: its seal ID (by default the current one), the bound
fields it bound (by default none), and whether it bound the record ID (by
default yes). Rows sealed with it keep opening, `Record::seal` writes the new
declaration, and a [sweep](reencryption-sweep.md#binding-declaration-changes)
reseals the rest. Rows of the old declaration are recognized by the fingerprint
in their header. Close the window, by deleting `legacy(…)`, only after a
complete verification pass counts no legacy-binding rows; the schema manifest
lists open windows.

Removing a bound value or changing its kind is outside that window: those values
must be resealed under an explicitly planned path of your own.

## ID hygiene

Seal IDs, index IDs, and kind IDs are generated UUIDs, never derived from a
Rust type name and never copied from documentation:

```sh
uuidgen
```

Either case parses; these pages use the lowercase form. Generate one ID per
seal, index, and kind of bound value, and keep it unchanged for the life of the
data: renaming a Rust type does not change an ID, and reusing an ID makes two
things one. Two examples in this repository share an ID only where they mean one
seal, as the SQLite and searchable examples share the tutorial's `UserEmail`; a
`UserEmail` marker in another example is a different seal with its own ID,
because the Rust name is not the identity.

Each check covers a different set: a bound list that lists one kind twice fails
the build; `assert_unique_ids!` rejects seal and index IDs shared by listed
markers; and a [manifest snapshot](integration.md#guarding-the-schema-in-ci)
makes any change to the IDs you have chosen a reviewable diff.

Key IDs follow separate rules, in [choosing keyrings](choosing-keyrings.md).

## What to read next

- [Choosing keyrings](choosing-keyrings.md): custody, the failure modes a
  binding cannot catch, and testing the choice.
- [Shredding a tenant](shredding.md): what destroying a tenant's keys does and
  does not remove.
- [Integration design](integration.md): persistent schema, storage boundaries,
  search, and ORMs.
- [Wire format](wire-format.md#binding): the exact binding bytes and the
  binding fingerprint.
- [Glossary](glossary.md): binding, bound value, record, partition.
