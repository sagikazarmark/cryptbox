---
status: accepted
---

# A seal declares how values are sealed, and may be its own value

> Amended by [ADR-0012](0012-a-record-is-a-context-layer-over-a-seal.md):
> a seal no longer declares a record flag. It declares its identity and
> encoding, and knows nothing of the context its values are sealed in.

The `Field` trait becomes `Seal`, and a seal may be its own value type. A seal
declares everything that decides how its values are sealed: its ID, value type,
codec, padding, scope, record flag, and blind indexes. `Sealed<S>` is a value
sealed with seal `S`, and a value sealed with one seal does not open as
another. "Field" is freed for the members of a record.

A seal takes one of two forms:

```rust
// A marker: the value is a separate type, which several seals can share.
#[derive(Seal)]
#[cryptbox(id = "…", value = Address, codec = Json)]
struct BillingAddress;

// Self-valued: the type is its own value.
#[derive(Seal)]
#[cryptbox(id = "…", transparent)]
struct UserEmail(Secret<String>);

#[derive(Seal, Serialize, Deserialize)]
#[cryptbox(id = "…", codec = Json)]
struct ProfileResponse { … }
```

- **Renames:** `Field` → `Seal`, `FieldId` → `SealId`, `field_id!` → `seal_id!`,
  `derive(Field)` → `derive(Seal)`, and `BlindIndexSpec::Field` →
  `BlindIndexSpec::Seal`. The derives' `field =` key becomes `seal =`, and key
  sources receive a `SealId`.
- **Two forms, one trait.** A self-valued seal sets `type Value = Self`. The trait
  already allows this; only the derive changes.
  - On a unit struct, `derive(Seal)` requires `value = T`.
  - On any other struct, the type is its own value, and `value` is rejected.
- **The codec is always stated, never inferred from a shape:**
  - `codec = C` encodes the value with `C`: for a self-valued seal, the whole
    type.
  - `transparent`, allowed only on a self-valued seal with exactly one field,
    stores that field alone: with `codec = C` if given, or else with the built-in
    default of the field's type. The derive writes the adapter that wraps and
    unwraps it.
  - A marker without `codec` takes the built-in default of its value type.
    Anything else is a build error that asks for `codec` or `transparent`.
- **Only four types have a default codec,** and they keep it permanently:
  `String` and `Secret<String>` use UTF-8, and `Vec<u8>` and `Secret<Vec<u8>>`
  use raw bytes. `Plaintext` leaves the public API: it becomes a private, sealed
  lookup that only the derive uses, and `derive(Plaintext)` is removed. A
  hand-written `Seal` impl names its codec.
- **In `#[derive(Record)]`, the seal's name becomes optional.** A member marked
  just `seal` is sealed as its own type (`#[cryptbox(seal)] email: UserEmail` is
  stored as `Sealed<UserEmail>`). A member whose type is not a seal fails to
  compile on the type mismatch; nothing is inferred from names. Every member
  still says how it is stored: treating an unmarked member as its own seal would
  report a forgotten `plaintext` as a cascade of type errors in generated code
  instead of one message.
- **Blind indexes over a self-valued seal** map the stored value to the query type
  with the existing `project = fn` key (`project = UserEmail::as_str`).

## Considered Options

- **Keep `Field`**: rejected. It describes a database column, while sealing
  whole responses, messages, or documents is just as valid, and a later record
  API needs "field" for its members.
- **Other names**:
  - `Purpose` (as in .NET Data Protection): accurate, but abstract in code.
  - `SealSpec`: matches `BlindIndexSpec`, but names the declaration rather than
    the concept.
  - `Label` (the NIST SP 800-108 partner of "context"): collides with the
    spec's fixed labels and custody labels.
  - `Kind`, `Schema`, `Profile` (retired), `Policy`, `DataClass`: vague,
    overloaded, or on another axis.

  `Seal` reads well both as a noun for a marker ("sealed with the `UserEmail`
  seal") and as an ability for a self-valued type, the way `serde::Serialize` does.
- **Self-valued only**, reversing ADR-0001: rejected. A prototype
  (`prototype/self-valued-seals`) found three costs for scalar values:
  - A `String` from a request body must be moved or cloned into the newtype
    before sealing, and unwrapped after opening.
  - Newtypes spread into records and request and response types, which then
    need `Serialize` or `Deserialize` on them.
  - `Plain<S>` wraps twice.
- **Markers only**, the status quo: rejected. A whole payload needs two types,
  and `derive(Plaintext)`'s newtype mode existed only to approximate a
  self-valued seal with a newtype value under a marker.
- **Choosing the codec's target from the struct's shape** (a single-field
  tuple struct encodes its field): rejected, as in ADR-0001. Refactoring
  `UserEmail(String)` into a struct with a named field would silently change
  the stored bytes. `transparent` states it.
- **Keep `Plaintext` open to applications**: rejected. It is the extension point
  through which a crate can change a type's default codec, behind a Cargo
  feature or in a new version, and silently change stored bytes downstream.
  Its remaining uses are covered by `transparent` and `codec =`.

## Consequences

- **Stored bytes are unchanged.** IDs keep their values, and no persistent label
  names a field. A marker and a self-valued seal with the same ID and codec read
  each other's values, which the prototype checks. Moving a seal from one form to
  the other is not a migration.
- **The API breaks, before 1.0:**
  - Every rename above.
  - Applications that implement `Plaintext` or derive it move to
    `transparent`, or name `codec` on the seal.
  - The schema manifest prints `seal <id>` instead of `field <id>`, so
    manifest snapshots change once, with no schema change.
- **ADR-0001 is amended.** The split between values and markers becomes a choice,
  not a rule. Its principle stays: a value type shared by several locations is
  never given an ID; each location is its own seal. Its "one derive writes two
  impls" exception for `derive(Plaintext)` is retired, and the `transparent`
  adapter replaces it.
- **ADR-0005 keeps its substance.** Its text says "field" for what is now a seal.
  The scope redesign (the empty scope as `()`, a record-bound scope, and typed
  key selection) is a separate decision.
- **Hygiene is unchanged:** `Secret<T>` still redacts and zeroizes, now also
  inside a self-valued seal.
- **Glossary:**
  - "Field" and "Field ID" become "Seal" and "Seal ID", with "field" reserved
    for record members.
  - "Plaintext type" shrinks to the four built-in defaults.
  - "Value type" notes that a self-valued seal is both a value and a seal.
- **Implementation order**, one commit each:
  1. the renames;
  2. `derive(Seal)` for both forms, with `transparent`;
  3. `Plaintext` closed and `derive(Plaintext)` removed;
  4. a bare `seal` in `derive(Record)`;
  5. the examples and guides: `key_rotation`'s `Email` plus its `UserEmail`
     marker become one self-valued seal, and `custom_field`'s `Handle` becomes
     `Handle(Secret<String>)` with `codec = HandleCodec`.
