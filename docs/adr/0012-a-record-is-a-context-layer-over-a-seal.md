---
status: accepted
---

# A record is a context layer over a seal

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
- **The manifest reports contexts per record.** A seal entry lists its seal ID,
  codec, and padding. A record entry lists the kind of its record ID and its
  context fingerprint, beside its seals, record ID, and plaintext fields.
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
- **The API breaks, before 1.0:** `Sealed` and `Prepared` gain a context parameter
  that defaults to `()`; `Seal::RECORD`, `__private::seal_in_record`, and
  `__private::open_in_record` go; `Context`, `ContextKind`, `InRecord`, the `*_in`
  methods, and `Record::Context` are added. Manifest snapshots change: seal
  entries lose `record` and `context`, and record entries gain them.
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
