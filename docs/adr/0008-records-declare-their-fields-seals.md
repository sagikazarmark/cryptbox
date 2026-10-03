---
status: accepted
---

# Records declare their fields' seals; the record ID is a bound part

> Amended by [ADR-0012](0012-a-record-is-a-context-layer-over-a-seal.md):
> a record's context is named by
> its stored fields' types, `Sealed<F, InRecord<Id>>`, and its fields' seals
> know nothing of the record.

> Amended by [ADR-0009](0009-scopes-have-views.md). The derives' attributes are
> named after them: `#[record(…)]`, `#[record_id]`, `#[seal(…)]`, and
> `#[blind_index(…)]` replace `#[cryptbox(…)]`. A record field without
> `#[seal…]` is stored as it is, the sealed struct defaults to `Sealed{Record}`,
> and a record has one keys view.

> Amended by [ADR-0010](0010-records-carry-their-bound-values.md). Every record
> field has one role in one attribute namespace: `#[cryptbox(record_id)]`,
> `bound`, `seal = "…"`, or `plaintext`, and a field without one fails the
> build. The stored form defaults to `Stored{Record}`, and a blind index is
> declared on its field.

A record declares a seal for each of its sealed fields, and every value is bound
to its seal ID, its scope's values, and, inside a record, the record ID:

```rust
#[derive(Record)]
#[cryptbox(record_id = id, sealed = SealedCustomer)]
struct Customer {
    #[cryptbox(plaintext)]
    id: i64,
    #[cryptbox(id = "…", scope = Tenant, index(EmailLookup as email_lookup))]
    email: String,
    #[cryptbox(id = "…", scope = Tenant)]
    note: String,
}
```

Each field then is its own seal by construction, so a value moved to another
field, table, scope, or row fails to open, and blind indexes of different fields
never share bytes.

- **A seal's ID is required** and always bound first. `type Scope` replaces
  `type Binding`:
  - `()` is the empty scope, the default, and replaces `FieldOnly`: a value is
    bound to its seal ID alone.
  - `#[derive(Scope)]` replaces `#[derive(Binding)]`, `Tenant` stays a preset,
    and the derives' `binding = …` key becomes `scope = …`.
  - `Seal::RECORD` and the `record` flag of `#[derive(Seal)]` are removed.
- **`#[derive(Record)]` declares a seal per field.** A sealed field takes the keys
  of `#[derive(Seal)]` (`id`, `scope`, `codec`, `padding`) plus `index(…)`, and
  the derive generates a seal type for it, named after the record and the field
  (`CustomerEmail`) unless `name = …` says otherwise, as `derive_builder` and
  `strum` name the types they generate. The type takes the field's visibility,
  the least at which the sealed struct's field can name it. The field's type is
  the seal's value type. The generated seal is an ordinary seal: blind indexes
  name it with `seal = CustomerEmail`, and the manifest lists it by its ID.
- **A field can instead use an existing seal**, with `seal = F` or, for a field
  whose type is its own seal, a bare `seal` (ADR-0007). Using one seal for two
  fields of a record fails the build. Sharing a seal across records or with
  standalone values makes those locations one domain, deliberately.
- **The record ID is a bound part of the scope, not a separate slot.** A
  generated seal's scope is its declared scope plus a record part: a bound-only
  part with the kind of the record ID's type, whose part ID is the nil UUID.
  Declared part IDs are already never nil, so the record part cannot collide
  with one and always sorts first. The wrapper
  that adds it, `Recorded<S, Id>`, is public, so a hand-written seal can be
  record-bound too. Like any bound part, the record never scopes keys or blind
  indexes, and its value comes from the row: opening checks it.
- **Scope values are supplied by the caller.** `Record::seal` and `Record::open`
  take the record's scope; every seal of a record shares one scope type. The
  record ID is read from the row, as today. A scope never comes from the stored
  row, because a row an attacker rewrote could then name another tenant.
- **Key sources are unchanged** for now: they receive the seal ID and the
  `KeyScope`. Since every field has its own seal ID, a source can route a
  record's `iban` and `email` to different keyrings. Typing key sources by their
  scope's key parts is a separate decision.
- **Wire format.** The binding loses its record slot,
  `seal_id ‖ count ‖ (part_id ‖ kind ‖ lp(value))*`, and the binding fingerprint
  loses its record flag, since the record part's ID, kind, and role are in the
  fingerprint like any part's.

## Considered Options

- **Reusable seals plus a record-type ID** (the first draft of this record):
  rejected after review. With a seal describing a kind of value rather than a
  location:
  - two fields of one seal in a row, such as `home` and `work`, could be swapped;
  - standalone columns of one seal could swap values;
  - blind indexes of one seal in several tables could be joined.

  Closing these needed a reuse check, record-type IDs in blind indexes, and a
  tag in the record slot. A seal per field closes them at the root, as ADR-0001
  intended: each storage location has its own ID. ADR-0001 also deferred a
  record-level derive "as optional sugar that expands to the same field markers",
  which this is.
- **A record parameter on `Sealed`** (`Sealed<S, R>`): unnecessary. A generated
  seal is always record-bound, so its type alone fixes the binding arguments.
- **The record flag on the seal**, the status quo: superseded. A seal declared on
  its record's field states its record binding where it is stored.
- **A `WithRecord<S>` scope written by the application**: replaced by the derive
  adding the record part. The declared `scope = Tenant` stays true of the field.
- **An attribute macro that rewrites field types** (`email: Sealed<String>` on the
  model): rejected. Derives expand to impls an application could write by hand,
  and the plaintext struct stays the model.
- **Scope values read from the stored row**: rejected, as in ADR-0005. An
  attacker who can write rows could copy another tenant's value into their own
  row, rewrite its tenant column, and have it open in their own request.
- **An ambient current scope** (a task-local set by middleware): rejected. It is
  hidden global state, which ADR-0004 and ADR-0006 avoided.
- **A scope field on the record** (`tenant: TenantId`, used as the scope when
  sealing and checked against the caller's when opening): deferred. Data that
  is trusted in one direction and only checked in the other is easy to misuse,
  and passing the scope is already correct. It can be added later without a
  breaking change.
- **An optional seal ID**, with `scope = ()` binding nothing: rejected. Seals
  without an ID over one scope would read each other's values, and the manifest,
  duplicate checks, and custody routing all key on the ID. This was 0.5's
  `Unbound`, which ADR-0001 removed.

## Consequences

- **Stored bytes change for every value and blind index**, since the record slot
  and the fingerprint's record flag go. Nothing has been released since 0.5.0,
  whose values are already unreadable (ADR-0005), so no migration is needed; the
  test vectors are regenerated.
- **The API breaks, before 1.0:**
  - `Binding` becomes `Scope`, `FieldOnly` becomes `()`, and `binding = …`
    becomes `scope = …`.
  - `Seal::RECORD`, the `record` flag, and `InRecord` are removed. A record-bound
    seal's binding arguments are its scope and its record ID.
  - `#[derive(Record)]` renames `record = id` to `record_id = id`, and its fields
    declare seals with `id = …` instead of naming marker types.
- **ADR-0005 is amended:** the record is a bound part that the record adds, not a
  flag on the seal. **ADR-0007 keeps** the bare `seal` for a field whose type is
  its own seal.
- **Other modules follow:**
  - The row planner and sweeps build the record part from the row's record ID,
    as they build the other parts. Moving a seal into or out of a record changes
    its declaration, which a legacy-binding window covers like any scope change.
  - The automatic `Plain` column and the installed keys serve seals with the
    empty scope, which excludes record-bound seals by type.
  - The manifest lists generated seals like any other, and can group them by
    record.
- **Glossary:** "Binding", "Binding arguments", "Record", and "Scope" are
  rewritten; "Seal" notes that a record declares its fields' seals.
