# Bind values to a scope

A binding is the cryptographic domain of a value: the field it belongs to, the
values of the field's declared scope, such as a tenant, and its record when the
field binds one. This page explains how to declare a scope, which role each part
should have, and where each bound value must come from.
[Documentation](README.md) · [Choosing keyrings](choosing-keyrings.md).

Start from [encrypt your first field](first-field.md), whose field binds values
to its field ID alone. Add a scope when values of different tenants, orgs, or
residencies must not be interchangeable, or when their keys must differ.

## Shape is schema, values are arguments

A binding has two halves, and they change on different schedules:

| Half | Where it is declared | When it changes |
| --- | --- | --- |
| **Shape**: part IDs, kinds, roles, and the record flag | The field and its `Binding` type | Only through a [shape migration](#change-a-binding-shape) |
| **Values**: this org, this workspace, this record | The binding arguments of each call | Every call |

One field never seals with different part sets on different calls: that would
give one value two valid encodings. The shape is persistent schema exactly as a
field ID or codec is, and every envelope carries a fingerprint of it so a
reader that expects another shape reports `Error::BindingMismatch` instead of an
authentication failure.

## Declare a scope

A `Binding` is data only: it declares its parts and returns their values. The
library sorts, frames, and validates the bytes, so no application writes binding
bytes. With the `derive` feature, each field of the struct is one part:

```rust
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Binding)]
#[cryptbox(index_args = OrgSearch)]
pub struct OrgWorkspace {
    /// The key scope and shred unit.
    #[cryptbox(part = "59881c28-3003-4047-847f-d7cc73b140e5", keys)]
    pub org: [u8; 16],
    /// Bound only: it separates ciphertext without scoping keys or indexes.
    #[cryptbox(part = "78f0169a-f024-402b-9cdf-f436864fa17f")]
    pub workspace: [u8; 16],
}

#[derive(cryptbox::Field)]
#[cryptbox(
    id = "2cef6a47-3e20-42dc-a319-56022cb4cf30",
    value = String,
    binding = OrgWorkspace,
    record,
    indexes(EmailLookup),
)]
pub struct CustomerEmail;
```

`EmailLookup` is a blind index over the field, declared as in the
[blind-index example](../examples/blind_indexes.rs).
The derive generates `OrgSearch`, the index arguments of the `keys` and `index`
parts, and implements `FromIndexValues` so an adapter such as a
[Restate object key](restate.md#object-keys) can parse them back. A part holds a
UUID, an `i64`, or bytes; an application's own ID type can hold one by
implementing `PartType`. Every part ID is a generated UUID: see
[ID hygiene](#id-hygiene).

`FieldOnly` and `Tenant` are ready-made presets. `FieldOnly` has no parts: unless
the field also binds a record, it is the
[empty binding](wire-format.md#binding), bound to the field ID alone. `Tenant` has one
bytes `keys` part. Use a preset until its shape is too coarse, then declare a
scope.

## Choose a role for each part

Every part is bound into the ciphertext. The role says what else it scopes, and
it is the decision with the most consequences:

| Role | Keys | Blind indexes | Shredding | Use it for |
| --- | --- | --- | --- | --- |
| `keys` | Scopes key custody | Scopes indexes | The [shred unit](shredding.md) | The value whose data must be destroyable and separately keyed, such as an org |
| `index` | Shared | Scopes indexes | Never alone | A value a query always knows, when equal values in different ones must not share index bytes |
| bound only | Shared | Shared | Never alone | A value a query need not know, such as a workspace within an org |

Three consequences follow from the table:

- **A `keys` part must be known before rows are read.** Keys are resolved from
  the key scope, and the key scope comes from the `keys` values, so a read that
  cannot name them has no keyring to open anything with. Every query, job, and sweep is
  partitioned by key scope; a cross-scope report has to be assembled per scope.
- **A query must supply every `keys` and `index` value.** Blind-index probes are
  derived from the index arguments, which have no record and no bound-only
  parts, because a query knows neither. A value that a lookup cannot know must
  not scope indexes.
- **A role change is a migration** even though the binding bytes do not change,
  because it changes index derivation and custody. The shape fingerprint covers
  roles for exactly that reason.

A record ID is never a part: declare `record` on the field. It is always bound
only, since a record-scoped index could not be searched.

## Bound values come from an authorized source

Every bound value must come from a source the request has already been
authorized against — verified claims, a session, an authorized
[object key](restate.md#object-keys) — and never from the row being read.
Reading the org out of the row and then opening the row under it proves nothing:
whatever the row says will match what the row was sealed with.

| Source of a bound value | Verdict |
| --- | --- |
| Verified request claims, an authorized scope, job configuration | Correct |
| A `Record`'s own record ID, read from the row | Correct, and checked when the row opens |
| The row's tenant, org, or scope columns | **Never**: the check becomes a tautology |
| A client-supplied scope the request was not authorized for | **Never**: authorize first, then bind |

A `Record` is the one exception, and only for its record ID. Opening takes the
ID from the row, and every field that declares `record` fails to open under
another one, so a value copied from another row is rejected. Storage can still
return a whole authentic row in place of another, which no binding prevents:
when you asked for one record, compare the opened ID with the one you asked for.

A [migration sweep](reencryption-sweep.md#binding-shape-changes) has no request
to take a binding from, so it builds each row's binding from the row's own
columns. Its key scope still comes from the job, and a row whose `keys` columns
name another key scope is reported out of scope and left alone. Resealing a
value from a shape that did not bind those columns trusts them once, so sweep
such a change only over columns the application already trusts.

## Record IDs

A field that declares `record` binds every value to a record ID, so the ID must
exist before the first value is sealed:

- **The client generates it**, UUIDv7 recommended, so that inserts carry their
  ID. Sealing after an insert, against a database-assigned key, is not
  supported.
- **It need not be the primary key.** A row can keep its own surrogate key and
  carry a separate, stable record ID; what matters is that the ID never changes
  while sealed values exist.
- **It is never encrypted**, because opening the row needs it first.
- **Its kind is fixed**: a UUID, an `i64`, or bytes. Any `PartType` can hold
  one.

A field of a record that declares no record is bound to the record's scope
alone, and gets no check of the ID. Within a `Record`, `InRecord` passes the ID
to every field and binds it only where the field declares it.

## Seal and open under a scope

The binding arguments of a call are typed by the field
([`Args<F>`](https://docs.rs/cryptbox/latest/cryptbox/trait.Args.html)): `()` and
`RecordId` for a `FieldOnly` field, `&F::Binding`, or `(&F::Binding, RecordId)`.
A missing or extra record fails the build rather than the read.

The [tenant example](../examples/tenant_field.rs) is the complete program: a
field bound to `Tenant` with a record, one `EncryptionKeyring` per tenant behind a
`HashMap<KeyScope, _>` key source, and assertions that another record of the same
tenant fails authentication while another tenant's keyring reports
`UnknownEncryptionKey`. Run it from a checkout, and expect
`Tenant-bound round trip succeeded.`:

```sh
cargo run --locked --example tenant_field
```

The crate's [quick start](https://docs.rs/cryptbox/latest/cryptbox/#quick-start)
shows the same program beside the field-only tier.

Whole rows are sealed and opened together through the
[`Record`](https://docs.rs/cryptbox/latest/cryptbox/trait.Record.html) trait and
derive, which pass one binding and record ID to every field and write each
field's blind indexes.

## Move a record between scopes

Changing a bound value is not an update of a column: the ciphertext is bound to
the old values. `Sealed::reseal_across` opens under the old binding and keys and
reseals under the new ones, without decoding the value through the field's
codec:

- **Every blind index of the moved value must be derived again**, because the
  index binding includes the `keys` and `index` parts. A stale index column is
  not wrong bytes the library can detect; it silently answers queries in the old
  scope. Derive the new indexes from the authenticated plaintext with
  `BlindIndexSpec::derive_with`, and write ciphertext and indexes in one atomic
  write.
- **A move across key scopes crosses custody.** The value leaves the reach of
  the old scope's keys, so it will survive that scope being
  [shredded](shredding.md). Where residency or custody rules apply, treat the
  move as an export.
- **Nothing rewrites values in place by itself.** Reads never reseal, and a
  bounded [sweep](reencryption-sweep.md) is the tool for a whole population.

## Change a binding shape

Adding a part, adding a record, or changing a role is a migration, not a
deployment. The procedure is a legacy-binding window, a reseal sweep, and
lookups over both index bindings until the window closes; rows of the old shape
are recognized by the fingerprint in their header. Follow
[binding-shape changes](reencryption-sweep.md#binding-shape-changes), and close
the window only after a complete verification pass counts no legacy-binding
rows.

Removing a part or changing a part's kind is outside that window: those values
must be resealed under an explicitly planned path of your own.

## Keys follow the key scope

Operations take their keys directly, and the library passes the key source the
field and the binding's key scope. Which keyring protects which scope is
application code — and sealing with the wrong one succeeds silently. Read
[choosing keyrings](choosing-keyrings.md) before you wire a scope to a keyring,
and [shredding](shredding.md) before you rely on destroying one scope's keys.

## ID hygiene

Field IDs, index IDs, and part IDs are generated UUIDs, never derived from a
Rust type name and never copied from documentation:

```sh
uuidgen
```

Either case parses; these pages use the lowercase form. Generate one ID per
logical field, index, and part, and keep it unchanged for the life of the data:
renaming a Rust type does not change an ID, and reusing an ID makes two things
one. Two examples in this repository share an ID only where they mean one logical
field, as the SQLite and searchable examples share the tutorial's `UserEmail`; a
`UserEmail` marker in another example is a different field with its own ID,
because the Rust name is not the identity.

Each check covers a different set: `#[derive(Binding)]` rejects a nil or
repeated part ID when it expands, and a hand-written binding fails the build on
the same shape; `assert_unique_ids!` rejects field and index IDs shared by
listed markers; and a
[manifest snapshot](integration.md#guarding-the-schema-in-ci) makes any change
to the IDs you have chosen a reviewable diff.

Key IDs follow separate rules, in [choosing keyrings](choosing-keyrings.md).

## What to read next

- [Choosing keyrings](choosing-keyrings.md): custody, the failure modes a
  binding cannot catch, and testing the choice.
- [Shredding a scope](shredding.md): what destroying a scope's keys does and
  does not remove.
- [Integration design](integration.md): persistent schema, storage boundaries,
  and search.
- [Wire format](wire-format.md#binding): the exact binding bytes and the
  shape fingerprint.
- [Glossary](glossary.md): binding, scope, key scope, shred unit.
