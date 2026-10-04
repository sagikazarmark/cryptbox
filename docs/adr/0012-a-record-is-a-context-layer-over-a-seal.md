---
status: accepted
---

# A record is a context layer over a seal

> Amended before 0.6, when nothing had stored these bytes: a part carries no
> slot and the fingerprint no role byte, both leftovers of the retired
> application-declared parts. A part's kind code names it, and the fingerprint
> label is `cryptbox/context-fingerprint/v1\0`. The context bytes, fingerprints,
> and test vectors below are those of
> [the wire format](../wire-format.md#seal-context), not ADR-0011's.
>
> Also amended before 0.6, as the API was trimmed: `Seal` declares no `Indexes`
> (a blind index is a `BlindIndexSpec` over its seal), `Prepared` and `prepare`
> are removed, and a context's values have `seal_in` and `open_in` only, with no
> `reseal_in` or `prepare_in`. `MaybeEncrypted` is `MaybeSealed`.

A seal declares only its identity and encoding. Which context a sealed value is
sealed under besides its seal ID is part of the sealed value's type, not the seal's:
`Sealed<F, C = ()>`. A record is the first such context, `InRecord<K>`:

```rust
#[derive(cryptbox::Record)]
pub struct Customer {
    #[cryptbox(record_id)]
    id: Uuid,
    #[cryptbox(seal = "2cef6a47-3e20-42dc-a319-56022cb4cf30")]
    email: String,
}

// The stored form's field is `Sealed<CustomerEmail, InRecord<Uuid>>`.
let stored: StoredCustomer = customer.seal(&keys)?;
let email = stored.email.open_in(&stored.id, &keys)?;          // what `Customer::open` does

let token = Sealed::<ApiToken>::seal(&value, &keys)?;           // standalone: `Sealed<ApiToken>`
```

- **A seal knows nothing of records.** `Seal` declares `ID`, `PADDING`, `Value`,
  `Codec`, and `Indexes`. The hidden `Seal::RECORD` constant goes, and so do the
  post-monomorphization assertions that read it. A seal works on its own, and its
  seal ID is still the first part of every context it is sealed under.
- **The context is the sealed value's second type parameter.** `()` is a standalone
  value, sealed under its seal ID alone, with `seal`, `open`, `reseal`, and
  `prepare`. A `Context` adds parts after the seal ID, and its values are sealed
  and opened with `seal_in`, `open_in`, `reseal_in`, and `prepare_in`, which take
  the context's value. Distinct names keep `Sealed::seal(..)` inferable where only
  the expected type names the seal.
- **The library owns contexts.** `Context` is sealed: only the library implements
  it, chooses its slots and kinds, and writes its bytes. `()` is never a
  `Context`, and every `Context` adds at least one part, so no context encodes like
  a standalone one. `InRecord<K>` is the only one: the record ID, of type `K`, in
  the nil slot.
- **`#[derive(Record)]` wires the record ID.** Its stored form holds
  `Sealed<Seal, InRecord<Id>>`, and it seals with `seal_in(.., &self.id, ..)` and
  opens with `open_in(.., &stored.id, ..)`, reading the ID from the row as before.
  `Record::Context` names the record's context.
- **Blind indexes and `Plain` are unaffected.** An index is derived under its seal
  ID alone, whatever the context of its seal's values. `Plain` and the installed
  keys serve standalone values only, as before.
- **The manifest reports contexts where they are registered.** A seal knows
  nothing of its contexts, so `Manifest::seal` lists its seal ID, codec, and
  padding only. A record entry lists the kind of its record ID and its context
  fingerprint, beside its seals, record ID, and plaintext fields.
  `Manifest::sealed::<F, C>()` registers a seal's values stored in context `C`,
  such as `()` for standalone values, and the seal entry lists that context's
  fingerprint. `duplicates()` reports a seal registered in several kinds of
  context, as `Duplicate::Context`: the manifest's guard against a record
  field's seal also stored standalone, effective only for contexts the
  application registers.
- **The wire format does not change.** Context bytes and fingerprints are those of
  ADR-0011, and every test vector stands.

## Considered Options

- **Removing the seal ID from the context, which would always come from outside**:
  rejected. The seal ID is the seal's identity: it keeps two seals that share keys
  from reading each other's values, separates their blind indexes, and is the only
  context a `Plain` column or an index query can know. ADR-0001 and ADR-0008 put
  identity on the seal for these reasons.
- **The record's context on the record, with stored fields of type `Sealed<F>` and
  a runtime check**: rejected. It moves the constant rather than removing it, and
  generic code, such as the migration planner, could not learn the context from a
  type.
- **A separate wrapper type, such as `InRecord<Sealed<F>>`**: rejected. Every
  byte-level impl (serde, `SQLx`, `Prepared`, `MaybeEncrypted`) would exist twice.
- **One method name for both forms, `seal(v, keys)` and `seal(v, &ctx, keys)`**:
  rejected. Both impls compile, but `let s: Sealed<F> = Sealed::seal(..)`, and
  generic code returning `Sealed<F>`, become ambiguous (E0034).
- **A seal that declares which contexts it may be used with**: deferred to #113.
  Without it, a record field's seal can be sealed standalone; see Consequences.

## Consequences

- **A record field's seal can be sealed standalone.** `Sealed::<CustomerEmail>::seal`
  and `Plain<CustomerEmail>` compile again. The value is written under the seal ID
  alone and fails to open as the record's, with `ContextMismatch`. A record field
  still cannot name an existing seal, so a generated seal is named only by its own
  record, and #113 tracks restoring the build error.
- **A misconfigured migration planner builds.** `RowPlanner::new` over a record
  field's seal, or `RowPlanner::for_rows` with a record ID of another kind, used
  to fail the build. Neither the seal nor the planner, which reads raw column
  bytes, has a type that says which context a column holds, so every row now
  reports `ContextMismatch`, and a verification pass counts each as a malformed
  row rather than aborting as misconfigured. A context parameter on the planner
  would not restore the check, since the caller would name it; #113 would.
- **The API breaks, before 1.0:** `Sealed` and `Prepared` gain a context parameter
  that defaults to `()`; `Seal::RECORD`, `__private::seal_in_record`, and
  `__private::open_in_record` go; `Context`, `ContextKind`, `InRecord`, the `*_in`
  methods, `Record::Context`, `Manifest::sealed`, and `Duplicate::Context` are
  added. Manifest snapshots change: seal entries lose `record` and list a
  `context` only for contexts `sealed` registers, and record entries gain both.
- **ADR-0011 is amended:** a record field's seal is no longer marked by a hidden
  `Seal::RECORD`, and its binding to the record ID is public as `InRecord`, sealed
  and opened by the record's derive or with `seal_in` and `open_in`. **ADR-0007** is
  amended: a seal no longer declares a record flag. **ADR-0008** is amended: a
  record's context is named by its stored fields' types, `Sealed<F, InRecord<Id>>`,
  where 0008 rejected `Sealed<S, R>` because a generated seal's type alone fixed it.
  **ADR-0005** is amended: a context's declaration is the sealed value's type.
- **Deferred:** further contexts, such as an org or a workspace, and composing
  them; whether a context can reach blind indexes, which would bring back
  partitions; a context role for record fields; restricting a seal's contexts
  (#113).
