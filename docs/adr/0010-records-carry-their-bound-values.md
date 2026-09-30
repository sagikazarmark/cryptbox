---
status: accepted
---

# Records carry their bound values; keys are passed in

A record stores the values its sealed fields are bound to as its own columns,
and every operation takes the keys to use. Custody, the part of a binding that
selects keys, is deferred until this foundation is in place:

```rust
#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "59881c28-3003-4047-847f-d7cc73b140e5")]
pub struct OrgId(Uuid);

#[derive(cryptbox::BoundId)]
#[cryptbox(kind = "78f0169a-f024-402b-9cdf-f436864fa17f")]
pub struct WorkspaceId(Uuid);

#[derive(cryptbox::Record)]
pub struct Customer {
    #[cryptbox(record_id)]
    id: Uuid,
    #[cryptbox(bound)]
    org: OrgId,
    #[cryptbox(bound)]
    workspace: WorkspaceId,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    #[cryptbox(blind_index(id = "ab78afa9-7aaa-499c-8239-037b7e136130",
                           across(workspace), bits = 32, normalize = Email))]
    email: String,
    #[cryptbox(plaintext)]
    created_at: OffsetDateTime,
}

let stored: StoredCustomer = customer.seal(&keys)?;
let customer = Customer::open(stored, &keys)?;          // bound values authenticated
authz.require(user, customer.org, customer.workspace)?;
```

- **Bound values are the application's own ID types.** `#[derive(BoundId)]`
  declares the kind of value, `#[cryptbox(kind = "…")]`, once on the type. It
  replaces scope structs, `#[part]`, and views: there are no part UUIDs to copy.
- **A record's bound values are its columns.** Every field has one role:
  `record_id`, `bound`, `seal = "…"`, or `plaintext`. Every sealed field is
  bound to its seal ID, to all of the record's bound values, and to the record
  ID. The stored form is `Stored{Record}`, with `Sealed<F>` in place of each
  sealed field and a `BlindIndex<S>` column per index. A field without a role
  fails the build, so nothing is stored as plaintext by accident.
- **Keys are passed in.** `seal`, `open`, and `probes` take the keys to use
  (`Keys`, or a keyring). Which keys protect which values is application code,
  as ADR-0006 decided; the library no longer asks a key source. With per-tenant
  keys, another tenant's row fails to open with `UnknownEncryptionKey`.
- **Opening authenticates the row's bound values, and the caller authorizes on
  them.** A bound value read from the row cannot be changed without failing
  authentication, so the record ID and bound values are taken from the stored
  row. `open_expecting` compares expected values with the stored columns before
  it decrypts. Search derives probes from the bound values the index is
  partitioned by, supplied by the caller; `open_matching` checks each row's
  partition values against them before decrypting, returns one result per row,
  and hands back each hit's authenticated bound values.
- **A blind index is declared on its field** and partitioned by all of the
  record's bound values by default. `across(…)` names the bound values it spans,
  which widens the equality it leaks, visibly. A query supplies the remaining
  partition values.
- **A standalone value** (not a row) uses `#[derive(Seal)]`, names its bound
  value types and whether it binds a record, and takes their values explicitly.
- **The fingerprint** covers each part's ID and kind and the record's kind. The
  role byte stays in the encoding, written `03` for every part; code `01`, the
  keys view, is no longer written. Changing which keys protect a value is key
  management, detected by key IDs and handled by a key-rotation sweep, not a
  binding change.
- **One attribute namespace, `#[cryptbox(...)]`.** Derive helper names cannot be
  written as paths; a bare `#[seal]` can silently shadow a user's attribute
  macro or clash with another derive's strict parser. `#[cryptbox(stored(...))]`
  forwards attributes (`derive`, `serde`, `sqlx`, `diesel`, `sea_orm`) to the
  stored form and its index columns.
- **A migration is an attribute.** `#[cryptbox(seal = "…", legacy(…))]` names
  the declaration a field had before. It is open-only and listed in the schema
  manifest; deleting it closes the window.
- **Deferred: custody.** It can return as keys that carry their owner
  (`Keys<OrgId>`), checked by `seal` and `open`, without changing the
  fingerprint or stored bytes.

## Considered Options

- **Keys views and typed key sources** (ADR-0009): superseded. Custody typed by a
  subset of the scope needed views with copied part IDs, two key-source traits
  on every signature, and a blind-index source even without indexes, and a
  keyring still served every keys view, so a wrong keyring sealed silently.
- **A custodian handle holding one custody value and its keys**: deferred with
  custody. It returns as keys that carry their owner.
- **Scope arguments supplied by the caller for records**: rejected. Real rows
  store their tenant and workspace columns anyway; a second, unchecked copy in
  the call site let a row be stored under one workspace and sealed to another.
- **Per-concept helper attributes** (`#[seal]`, `#[part]`, `#[record_id]`):
  replaced. Prototypes showed silent shadowing of a user's attribute macro and
  failures when another derive parses the same helper strictly.
- **`anchor`** for bound values: rejected. In a cryptography library it reads as
  a PKI trust anchor.
- **Plaintext by default** (ADR-0009): reversed. An explicit role per field is a
  build error where a manifest diff is only a review signal.
- **Sealing in serde or ORM hooks, or an ambient per-task key context**:
  rejected, as ADR-0004 rejected ambient keys. serde and database layers carry
  only ciphertext; sealing and opening are explicit calls.

## Consequences

- **Stored bytes change only in the fingerprint** of seals whose scope had
  `keys` parts, `Tenant`'s included. Binding and index-binding bytes do not
  change. Nothing has been released since 0.5.0; changed fingerprints are
  recomputed independently.
- **The API breaks, before 1.0:** `Scope`, `#[part]`, views and `FromParts`,
  `Recorded` and `SealScope`, the `Args` forms, `Seal::Keys` and `Record::Keys`,
  `EncryptionKeySource` and `BlindIndexKeySource`, `KeysOf`-typed planner and
  window APIs, and the per-concept helper attributes go. Sweeps are run per set
  of keys by the application.
- **ADR-0009 is superseded** except for resolving keyrings in the typed layer.
  **ADR-0005** is amended (bound values are read from the row and
  authenticated), **ADR-0006** is amended (keys are passed in without a source
  trait), and **ADR-0008** is amended (a record's roles and attribute syntax).
- **Glossary:** "bound value" replaces scope, part, and view; "keys view",
  "index scope", and "key source" are retired; "custody" is reserved for the
  deferred follow-up.
- **Open for the implementation:** `Option<T>` fields as `Option<Sealed<F>>`,
  nested records, sealed `Vec`s as one value, and the stored form's field order
  as schema for binary formats. A throwaway prototype of this design (sqlx,
  Diesel, and serde) added:
  - a text form for sealed values and blind indexes in human-readable serde
    formats, which today write byte arrays;
  - a named partition type per blind index in place of a positional tuple of
    bound values, which a type checks only when the values' types differ;
  - distinct errors for a row outside a query's partition and a row an
    `open_expecting` check rejects;
  - whether sealing a record that has blind indexes with an encryption keyring
    alone fails the build rather than at run time;
  - `From<Sealed<F>> for Vec<u8>` and the `BlindIndex` equivalent, which an
    ORM's `serialize_as` needs and the orphan rule keeps applications from
    writing.
