# Bind values to a scope

A binding is the cryptographic domain of a value: the seal it is sealed with, the
values of the seal's declared scope, such as a tenant, and its record when the
seal binds one. This page explains how to declare a scope and the views that
decide what each part scopes, the seal's keys view and each blind index's
scope, and where each bound value must come from.
[Documentation](README.md) · [Choosing keyrings](choosing-keyrings.md).

Start from [seal your first value](first-field.md), whose seal binds values
to its seal ID alone. Add a scope when values of different tenants, orgs, or
residencies must not be interchangeable, or when their keys must differ.

## Declarations are schema, values are arguments

A binding has two halves, and they change on different schedules:

| Half | Where it is declared | When it changes |
| --- | --- | --- |
| **Declaration**: part IDs, kinds, the keys view, and the record's kind | The seal, its seal scope, such as `Tenant` or `Recorded<Tenant, i64>`, and its keys view | Only through a [declaration migration](#change-a-binding-declaration) |
| **Values**: this org, this workspace, this record | The binding arguments of each call | Every call |

One seal never seals with different part sets on different calls: that would
give one value two valid encodings. The declaration is persistent schema exactly as a
seal ID or codec is, and every envelope carries a fingerprint of it so a
reader that expects another declaration reports `Error::BindingMismatch` instead of an
authentication failure.

## Declare a scope and its views

A `Scope` is data only: it declares its parts and returns their values. The
library sorts, frames, and validates the bytes, so no application writes binding
bytes. With the `derive` feature, each field of the struct is one part, with its
part ID:

```rust
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
pub struct OrgWorkspace {
    #[part("59881c28-3003-4047-847f-d7cc73b140e5")]
    pub org: [u8; 16],
    #[part("78f0169a-f024-402b-9cdf-f436864fa17f")]
    pub workspace: [u8; 16],
}

/// A view of `OrgWorkspace`: the org alone.
#[derive(Clone, Hash, PartialEq, Eq, cryptbox::Scope)]
pub struct Org {
    #[part("59881c28-3003-4047-847f-d7cc73b140e5")]
    pub org: [u8; 16],
}

#[derive(cryptbox::Seal)]
#[seal(
    id = "2cef6a47-3e20-42dc-a319-56022cb4cf30",
    value = String,
    scope = cryptbox::Recorded<OrgWorkspace, [u8; 16]>,
    keys = Org,
    indexes(EmailLookup),
)]
pub struct CustomerEmail;
```

Parts have no roles. A **view** of a scope is another scope whose parts are
parts of it, matched by part ID and kind, as `Org` is of `OrgWorkspace`; its
values are projected from the scope's by part ID. Views decide what else a part
scopes:

- the seal's **keys view**, `keys = Org`, holds the parts
  [key custody follows](#choose-the-keys-view). Without `keys`, it is the
  whole scope, which fits `()` and `Tenant`;
- each blind index's **index scope** holds the parts that
  [partition the index](#choose-each-blind-indexs-scope), here for
  `EmailLookup`;
- a part in no view, here the workspace, is bound only: it separates
  ciphertext and nothing else.

A view is checked when it is first used: one with a part its scope lacks fails
the build. The derive also implements `FromParts`, which builds a scope back
from its part values, so views can be projected and an adapter such as a
[Restate object key](restate.md#object-keys) can parse one. A part holds a
UUID, an `i64`, or bytes; an application's own ID type can hold one by
implementing `PartType`. Every part ID is a generated UUID: see
[ID hygiene](#id-hygiene).

`()` and `Tenant` are ready-made scopes. `()`, the empty scope, has no parts:
unless the seal also binds a record, it is the
[empty binding](wire-format.md#binding), bound to the seal ID alone. `Tenant` has one
bytes part, and is its own keys view. Use a preset until its declaration is too
coarse, then declare a scope.

A record ID is never a declared part: a seal binds one with the seal scope
`Recorded<S, Id>`, which adds it as one more part under the nil part ID. It is
in no view, since a record-scoped index could not be searched.

## Choose the keys view

Every part is bound into the ciphertext. Whether it also scopes key custody is
the decision with the most consequences:

| Part | Keys | Shredding | Use it for |
| --- | --- | --- | --- |
| In the keys view | Scopes key custody | The [shred unit](shredding.md) | The value whose data must be destroyable and separately keyed, such as an org |
| In no view | Shared | Never alone | A value that separates ciphertext only, such as a workspace within an org |

Two consequences follow from the table:

- **The keys view must be known before rows are read.** Keys are resolved from
  its values, so a read that cannot name them has no keyring to open anything
  with. Every query, job, and sweep is partitioned by keys view; a cross-scope
  report has to be assembled per scope. A value of a part in the keys view can't
  be empty.
- **Changing the keys view is a migration** even though the binding bytes do not
  change, because it changes custody. The binding fingerprint marks the parts of
  the keys view for exactly that reason.

## Choose each blind index's scope

A blind index names its own **index scope**, the parts that partition it: a view
of its seal's scope. A query supplies its values, and a stored index is derived
under the same values, projected from the scope its value was sealed under:

```rust
#[derive(cryptbox::BlindIndexSpec)]
#[blind_index(
    id = "ab78afa9-7aaa-499c-8239-037b7e136130",
    seal = CustomerEmail,
    scope = Org,
    bits = 32,
    query = str,
    normalize = normalize_email,
    normalizer = "email/1",
)]
pub struct EmailLookup;
```

- **An index scope holds the seal's keys view**, because a query selects index
  keys by it. A scope that leaves one of its parts out, or has a part the
  seal's scope lacks, fails the build when the index is first used.
- **Add a part a query always knows** when equal values in different ones must
  not share index bytes, such as a region. A value that a lookup cannot know,
  such as a workspace the query spans or the record, must stay out.
- **Two indexes over one seal may partition differently.** Without `scope`, a
  derived index is scoped by the seal's whole scope; an unscoped seal's index
  uses `()`.
- **Changing an index scope**, such as adding a part to it, changes that
  index's bytes, as changing its normalizer does: look up with
  `migrate::probes_across` over both scopes while a
  [sweep](reencryption-sweep.md#blind-indexes) derives every stored index again.

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
ID from the row, and every seal bound to the record fails to open under
another one, so a value copied from another row is rejected. Storage can still
return a whole authentic row in place of another, which no binding prevents:
when you asked for one record, compare the opened ID with the one you asked for.

A [migration sweep](reencryption-sweep.md#binding-declaration-changes) has no request
to take a binding from, so it builds each row's binding from the row's own
columns. Its keys view still comes from the job, and a row whose columns project
another keys view is reported out of scope and left alone. Resealing a
value from a declaration that did not bind those columns trusts them once, so sweep
such a change only over columns the application already trusts.

## Record IDs

A seal whose scope is `Recorded<S, Id>` binds every value to a record ID, so the
ID must exist before the first value is sealed:

- **The client generates it**, UUIDv7 recommended, so that inserts carry their
  ID. Sealing after an insert, against a database-assigned key, is not
  supported.
- **It need not be the primary key.** A row can keep its own surrogate key and
  carry a separate, stable record ID; what matters is that the ID never changes
  while sealed values exist.
- **It is never encrypted**, because opening the row needs it first. A
  `#[derive(Record)]` marks its field `#[record_id]`.
- **Its kind is fixed**: a UUID, an `i64`, or bytes, the kind of `Id`. Any
  `PartType` can hold one, and changing its type is a declaration change.

A record field whose seal binds no record is bound to the record's scope
alone, and gets no check of the ID. A `Record` passes the ID to every sealed
field and binds it only where the seal's scope is `Recorded`.

## Seal and open under a scope

The binding arguments of a call are typed by the seal
([`Args<F>`](https://docs.rs/cryptbox/latest/cryptbox/trait.Args.html)): `()` for
an unscoped seal, `&scope`, `(&scope, &record_id)` for a seal whose scope is
`Recorded`, or `((), &record_id)` for `Recorded<(), Id>`. A missing or extra
record is a type error rather than a failed read.

The [tenant example](../examples/tenant_field.rs) is the complete program: a
seal bound to `Tenant` with a record, one `EncryptionKeyring` per tenant behind a
`HashMap<Tenant, _>` key source, and assertions that another record of the same
tenant fails authentication while another tenant's keyring reports
`UnknownEncryptionKey`. Run it from a checkout, and expect
`Tenant-bound round trip succeeded.`:

```sh
cargo run --locked --example tenant_field
```

The crate's [quick start](https://docs.rs/cryptbox/latest/cryptbox/#quick-start)
shows the same program beside the unscoped tier.

Whole rows are sealed and opened together through the
[`Record`](https://docs.rs/cryptbox/latest/cryptbox/trait.Record.html) trait and
derive, which pass one binding and record ID to every sealed field and write each
seal's blind indexes. A record has one scope and one keys view, so one key
source serves all of its fields. A field without `#[seal…]` is stored as it is,
and the [schema manifest](integration.md#guarding-the-schema-in-ci) lists it by
name, so a field that should have been sealed shows up in review.

## Move a record between scopes

Changing a bound value is not an update of a column: the ciphertext is bound to
the old values. `Sealed::reseal_across` opens under the old binding and keys and
reseals under the new ones, without decoding the value through the seal's
codec:

- **Every blind index of the moved value must be derived again**, because
  each index binding includes the parts of its index scope. A stale index column is
  not wrong bytes the library can detect; it silently answers queries in the old
  scope. Derive the new indexes from the authenticated plaintext with
  `BlindIndexSpec::derive_with`, and write ciphertext and indexes in one atomic
  write.
- **A move across keys views crosses custody.** The value leaves the reach of
  the old scope's keys, so it will survive that scope being
  [shredded](shredding.md). Where residency or custody rules apply, treat the
  move as an export.
- **Nothing rewrites values in place by itself.** Reads never reseal, and a
  bounded [sweep](reencryption-sweep.md) is the tool for a whole population.

## Change a binding declaration

Adding a part, adding a record, or changing the keys view is a migration, not a
deployment. The procedure is a legacy-binding window, a reseal sweep, and
lookups over both index bindings until the window closes; rows of the old declaration
are recognized by the fingerprint in their header. Follow
[binding-declaration changes](reencryption-sweep.md#binding-declaration-changes), and close
the window only after a complete verification pass counts no legacy-binding
rows.

Removing a part or changing a part's kind is outside that window: those values
must be resealed under an explicitly planned path of your own.

## Keys follow the keys view

Operations take their keys directly, and the library passes the key source the
seal and the values of its [keys view](#choose-the-keys-view) (`Seal::Keys`),
projected from the binding arguments. A key source is typed by the keys view it
serves, as `EncryptionKeySource<Org>`, and a keys view is `Hash + Eq`, so it can
key a map of keyrings. A blind index's key source receives the same keys view,
projected from its index scope. Which keyring protects which scope is
application code — and sealing with the wrong one succeeds silently. Read
[choosing keyrings](choosing-keyrings.md) before you wire a scope to a keyring,
and [shredding](shredding.md) before you rely on destroying one scope's keys.

## ID hygiene

Seal IDs, index IDs, and part IDs are generated UUIDs, never derived from a
Rust type name and never copied from documentation:

```sh
uuidgen
```

Either case parses; these pages use the lowercase form. Generate one ID per
seal, index, and part, and keep it unchanged for the life of the data:
renaming a Rust type does not change an ID, and reusing an ID makes two things
one. Two examples in this repository share an ID only where they mean one
seal, as the SQLite and searchable examples share the tutorial's `UserEmail`; a
`UserEmail` marker in another example is a different seal with its own ID,
because the Rust name is not the identity.

Each check covers a different set: `#[derive(Scope)]` rejects a nil or
repeated part ID when it expands, and a hand-written binding fails the build on
the same declaration; `assert_unique_ids!` rejects seal and index IDs shared by
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
  binding fingerprint.
- [Glossary](glossary.md): binding, scope, keys view, shred unit.
