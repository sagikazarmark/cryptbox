---
status: accepted
---

# Runtime binding is the core; fields declare its shape

> Amended when implemented (#23). A `Record` reads its record ID from the stored
> row, because opening checks it: every field that declares `record` fails to
> open under another ID. Storage can still return a whole authentic row in place
> of another, which no binding prevents, so a lookup by ID compares the opened ID
> with the one it asked for. The binding itself still comes from an authorized
> source, and a record whose fields bind no record gets no check of its ID.

Every seal and open binds the ciphertext to a runtime **binding**: the field ID,
a declared scope (for example tenant, or org plus workspace), and optionally a
record ID. The binding bytes go into the AAD and the HKDF info. Tenant and
record are runtime values, and real tenancy is often more than one value, so
binding is a first-class argument rather than a fixed field-ID-only rule
extended later (#23, #24).

The binding's **shape** is fixed per field and is persistent schema. Its
**values** are supplied at each call. One field never seals with different
part sets on different calls, because that would give the same value two valid
AAD encodings.

- A scope is a data-only `Binding`:
  - `const PARTS` lists part UUIDs, value kinds, and roles.
  - `values()` returns the values in declared order.
  - Users never write bytes. The library sorts, frames, and validates the parts.
  - The derive checks the declaration at expansion. A hand-written impl gets a
    post-monomorphization assert as a backstop.
- Part roles:
  - `keys`: the part scopes key custody and blind indexes, and defines the unit
    you shred. It implies `index`.
  - `index`: the part scopes blind indexes only.
  - Unmarked parts are bound only.
  - A record is always bound only. It is never a `keys` or `index` part, since a
    record-scoped index could not be searched.
- Value kinds are fixed and canonical: uuid, i64, and bytes. There is no text
  kind. Parts are never optional, and a `keys` part value can't be empty.
- Scope structs own their values and implement `Hash + Eq`. `KeyScope` holds only
  the `keys` parts.
- `record` is a flag on the field, not a scope part. `FieldOnly` (tag `01`,
  byte-identical to earlier releases) and `Tenant` are ready-made presets.
- Wire format:
  - Tag `02 ‖ field_id ‖ record? ‖ count ‖ (part_id ‖ kind ‖ lp(value))*`, with
    parts sorted by part ID and at least one part present.
  - The header carries a 64-bit shape fingerprint over part IDs, kinds, and
    roles. It is diagnostic only: the expected shape always comes from the
    reader's type, and a mismatch reports `BindingMismatch`, not
    `AuthenticationFailed`.
  - Roles are in the fingerprint because a role change alters index derivation
    and custody, so it is a migration even though the AAD bytes don't change.
- Blind indexes take their own typed `IndexArgs` (the `keys` and `index` parts),
  because a query has no record. Each `keys` scope derives its own index keys.
- Naming:
  - The stored value is `Sealed<F>`, with `seal`, `open`, `prepare`, `reseal`, and
    `reseal_across`.
  - `open` returns the bare `F::Value`. Plaintext hygiene comes from value types
    such as `Secret<T>`.
  - `Plain<F, K>` exists only as the automatic sqlx column, and only for
    `FieldOnly` fields without blind indexes.
- `Field` gains `type Binding`, `const RECORD`, and `type Indexes`. `Indexes` lets
  `Plain<F>` and the `Record` derive reject a field whose blind index would not
  be written.

## Considered Options

- **Type-level binding only** (field ID in the AAD, with tenant and record added
  later): rejected. Every tenancy feature would be bolted on, and the automatic
  column would stay the default path even where it can't bind a row.
- **A generic user context with user-written AAD encoding** (`SealContext`,
  `ContextSealer<C>`): rejected. Users would own persistent-schema bytes,
  ambiguous concatenations would collide, and a context that also drives key
  selection lets stored bytes choose their own domain.
- **Four sealed modes** (FieldOnly, Tenant, Record, TenantRecord): superseded
  by declared parts. A tenant made of two values with different roles, where
  one is the shred unit and the other is only bound, can't be expressed as
  one opaque tenant ID.
- **A composite tenant ID only**: kept as a preset use of declared parts. On its
  own it forces custody and index scope to the full composite, so it can't
  express an index that spans part of the scope.
- **An encrypting Restate codec**: rejected. Restate compares journaled payload
  bytes on replay, and a random nonce breaks that. The Restate adapter
  journals `Sealed<F>` produced inside `ctx.run`.

## Consequences

- Supersedes the `Field` shape in [ADR-0001](0001-application-types-are-values-fields-are-markers.md)
  and its `Encrypted<F>` carrier. The value/field split from ADR-0001 stands.
  [ADR-0002](0002-authenticated-padding-flag.md) is unaffected.
- The automatic sqlx column and the process-wide keys cover only `FieldOnly`
  fields, because a column decoder cannot see a row or a scope. Bound fields are
  sealed and opened explicitly, or through the `Record` trait and derive.
- Changing a field's binding shape (for example, adding a workspace part) is a
  migration:
  - an explicit legacy-binding window, counted by fingerprint;
  - a reseal sweep;
  - probes over both index shapes while the window is open.
- The unit you can shred is the finest `keys` part whose root keys are stored
  independently. The manifest reports it for each field.
- Every bound value must come from an authorized source, such as verified claims
  or an authorized object key, never from the stored row. `keys` parts must be
  known before rows are read. The one exception is a `Record`'s record ID; see
  the amendment above.
- Record IDs are generated by the client (UUIDv7 recommended). Sealing after
  insert is not supported. A record ID doesn't have to be the primary key.
