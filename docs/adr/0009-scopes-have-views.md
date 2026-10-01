---
status: superseded by ADR-0010
---

# Scopes have views; key sources are typed by the keys view

> Superseded by [ADR-0010](0010-records-carry-their-bound-values.md), except
> for resolving keyrings in the typed layer, which stays.

> Amended when implemented. A legacy-binding window names the old keys view
> beside the old seal scope, `RowPlanner::legacy_binding::<Old, OldKeys>`, as
> do `migrate::open_across` and `migrate::probes_across`, since the old
> fingerprint and the old key source both depend on it.
> `restate::ObjectKey<B, K = B>` leads with the parts of a view `K` and takes
> `prefix(&K)`. `#[derive(Scope)]` takes `crate = "…"` in `#[scope(…)]`. The
> manifest reads a record's seals and plaintext fields from `Record::SEALS`,
> `Record::RECORD_ID`, and `Record::PLAINTEXT`, registered with
> `Manifest::record::<R>()`, and names the record by its seal IDs.

A scope is a struct of parts with no roles. What a part does beyond being bound
into the ciphertext is decided by **views**: other scope types whose parts are a
subset of the scope's. A seal names its scope and its **keys view**, which key
sources receive; a blind index names its own **index scope**:

```rust
#[derive(Clone, Hash, PartialEq, Eq, Scope)]
struct OrgWorkspace {
    #[part("59881c28-3003-4047-847f-d7cc73b140e5")]
    org: [u8; 16],
    #[part("78f0169a-f024-402b-9cdf-f436864fa17f")]
    workspace: [u8; 16],
}

#[derive(Clone, Hash, PartialEq, Eq, Scope)]
struct Org {
    #[part("59881c28-3003-4047-847f-d7cc73b140e5")]
    org: [u8; 16],
}

#[derive(Record)]
struct Customer {
    #[record_id]
    id: i64,
    #[seal(id = "…", scope = OrgWorkspace, keys = Org)]
    #[blind_index(EmailLookup as email_lookup)]
    email: String,
    created_at: i64,
}
```

- **Parts carry no roles.** `#[derive(Scope)]` declares each part's ID and kind;
  the `keys` and `index` roles and bound-only marking are removed.
- **A view is a scope whose parts are a subset of another's,** matched by part ID
  and kind. The subset is checked at compile time, and a view's values are
  projected from the scope's by part ID. A part in no view is bound only, which
  in practice is mostly the built-in seal ID and record ID.
- **A seal names its keys view** (`Seal::Keys`, `keys = …`, defaulting to the
  whole scope). Custody follows it, and a sweep is partitioned by it.
- **A blind index names its index scope** (`BlindIndexSpec::Scope`), a view of its
  seal's scope that contains the seal's keys view, since a query selects index
  keys from it. It replaces `IndexArgs`: a query passes `&IndexScope`, and two
  indexes over one seal may partition differently.
- **Key sources are typed by the keys view:**
  `EncryptionKeySource<K>::encryption_keyring(&self, seal: SealId, keys: &K)` and
  `BlindIndexKeySource<K>::blind_index_keyring(&self, index: IndexId, keys: &K)`.
  Keyrings and `Keys` implement both for every `K`. `KeyScope` is removed: a
  typed `K` is `Hash + Eq`, so it can key a map or a cache itself.
- **Keyrings are resolved in the typed layer.** `bound` and `envelope` take
  keyrings, and the binding encoding takes the seal ID as its 16 identity bytes,
  so no layer below the typed one names a seal or an index.
- **The fingerprint** covers the scope's parts and the record part, with role
  code `01` for a part in the keys view and `03` for any other; code `02` is no
  longer used, since index scopes belong to blind indexes, whose declaration
  changes go through `probes_across`.
- **A record has one scope and one keys view** (`Record::Keys`), so
  `Record::seal` takes one key source for all of its fields.
- **Derive attributes are named after their derive,** and `#[cryptbox]` is
  retired: `#[seal(…)]` on `#[derive(Seal)]`, `#[blind_index(…)]` on
  `#[derive(BlindIndexSpec)]`, `#[part("…")]` on the fields of
  `#[derive(Scope)]`, and for `#[derive(Record)]` an optional
  `#[record(sealed = …, attr(…))]` and these field attributes:
  - `#[record_id]`: the record ID, stored as it is;
  - `#[seal(id = "…", scope = …, keys = …, codec = …, padding = …, name = …)]`:
    the field's own seal;
  - `#[seal(F)]`: an existing seal; a bare `#[seal]`: a field whose type is a seal;
  - `#[blind_index(Spec as column, …)]`: the blind indexes it writes.
- **Record defaults:** the stored struct is `Sealed{Record}` unless
  `#[record(sealed = …)]` names it, and an unmarked field is stored as it is. The
  schema manifest lists each record's plaintext fields by name, so a forgotten
  `#[seal]` shows up as a snapshot diff.
- **Unchanged:** the seal ID is required and bound first; `Recorded<S, Id>` binds
  the record as a part under the nil part ID; `()` is the empty scope and `Tenant`
  a preset.

## Considered Options

- **Roles on parts**, the status quo: superseded. Roles tie custody and index
  partitioning to one struct, need a generated `index_args` struct and an erased
  `KeyScope` for key sources, and cannot let two indexes over one seal partition
  differently.
- **Separate role slots on the seal** (`keys = …, index = …, bound = …`, each a
  disjoint struct): rejected. Call arguments would be a composite of several
  structs, and moving a part between roles would move it between types. A view
  keeps one scope value and derives the rest.
- **The whole scope passed to key sources**: rejected. Custody must not depend on
  a bound-only part, which a row could supply, and a query has only the index
  scope.
- **Sealing unmarked record fields by default**: impossible, since each sealed
  field needs its own seal ID. **Requiring every field to say how it is stored**,
  the status quo, is dropped for plaintext by default, with the manifest's
  listing of plaintext fields as the safety net.
- **A `#[cryptbox::seal]` path**: impossible; Rust resolves derive helper
  attributes by their bare name only.

## Consequences

- **Stored bytes change only for seals whose scope had `index` parts:** their
  fingerprints lose code `02`. Binding and index-binding bytes do not change,
  since both already sort parts by part ID. Nothing has been released since
  0.5.0.
- **The API breaks, before 1.0:** part roles, `IndexArgs`, `FromIndexValues`,
  `KeyScope`, and `#[cryptbox]` go; key sources gain a type parameter; the row
  planner is configured with a keys value instead of a `KeyScope`; record fields
  are plaintext unless marked.
- **ADR-0005 is amended** (roles become views), **ADR-0006 is amended** (key
  sources receive the typed keys view), and **ADR-0008 is amended** (the record
  derive's attribute syntax and defaults).
- **Glossary:** "Key scope" becomes the keys view, "Index binding" is derived from
  a blind index's index scope, and "Binding part" loses its roles.
