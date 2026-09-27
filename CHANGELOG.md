# Changelog

## Unreleased

- **Breaking:** profiles are replaced by field marker types over the
  application's own value types (ADR-0001). `Field` merges the old `Field` and
  `EncryptionProfile`: it declares `const ID`, `const PADDING`, `type Value`,
  and `type Codec`, and every value is bound to its field. `Field::NAME`, the
  per-profile `Keys` context, `Binding`, `Unbound`, `FieldBound`,
  `ProfileContext`, and the `profile!` macro are removed. Wrapper types take
  only the field:
  `Encrypted<UserEmail>`, `Ciphertext<UserEmail>` (which now requires
  `F: Field`), `MaybeEncrypted<UserEmail>`, `Prepared<'_, UserEmail>`,
  `RowPlanner<'_, UserEmail>`, and `Sweep<'_, UserEmail>`. The unit `&()`
  binding context argument is dropped from every `*_with` method and from
  `RowPlanner::new`. Implicit forms (`encrypt()`, `decrypt()`, `prepare()`, and
  the automatic SQLx adapters) read `GlobalKeyContext`; a custom `KeyContext`
  can no longer be selected per field. Stored field-bound ciphertext and blind
  indexes are unchanged and need no data migration.
  Binding tag `00` is reserved, so data written with `Unbound` is no longer
  readable.
- **Breaking:** `Padding` is a const value instead of a sealed trait:
  `Padding::NONE`, `Padding::block(n)`, and `Padding::length(n)` replace
  `NoPadding`, `PadToBlock<N>`, and `PadToLength<N>`, with byte-identical
  output.
- Add `Plaintext`, which names a value type's default codec. The crate
  implements it permanently for `String` and `Secret<String>` (`Utf8`) and for
  `Vec<u8>` and `Secret<Vec<u8>>` (`Raw`), independent of features; `Utf8` and
  `Raw` now also encode the `Secret` wrappers with identical bytes. Applications
  can implement it for their own value types.
- **Breaking:** `Encrypted::new` accepts `impl Into<F::Value>` and is no
  longer `const`. The `From<T>` implementation for `Encrypted` is removed; use
  `Encrypted::new`.
- **Breaking:** low-level primitives take the field instead of a binding and
  context: `encrypt(F::ID, plaintext, keys)`, `decrypt(F::ID, …)`,
  `reencrypt(F::ID, …)`, and `needs_reencryption(F::ID, …)`.

  Migrating from 0.5:

  | 0.5 | Now |
  | --- | --- |
  | `cryptbox::profile! { P: String { id: "…", name: "…", codec: Utf8 } }` | `struct P;` plus `impl Field for P { const ID: FieldId = field_id!("…"); const PADDING: Padding = Padding::NONE; type Value = String; type Codec = Utf8; }` |
  | `impl EncryptionProfile<String> for P { type Binding = FieldBound<Self>; … }` | `impl Field for P { type Value = String; … }` |
  | `type Binding = FieldBound<Other>;` | `const ID: FieldId = Other::ID;` |
  | `binding: unbound,` | re-encrypt existing data under a field ID first |
  | `type Padding = PadToBlock<16>;` | `const PADDING: Padding = Padding::block(16);` |
  | `type Keys = …;`, `Field::NAME` | remove; install keys with `GlobalKeyContext::install` |
  | `Encrypted<String, P>`, `Encrypted::<_, P>` | `Encrypted<P>`, `Encrypted::<P>` |
  | `value.encrypt_with(&(), &keys)` | `value.encrypt_with(&keys)` |
  | `value.into()` into `Encrypted` | `Encrypted::new(value)` |
  | `encrypt::<FieldBound<F>>(bytes, &(), &keys)` | `encrypt(F::ID, bytes, &keys)` |
  | `impl BlindIndexMetadata for S` plus `impl BlindIndexSpec<str> for S` and `impl BlindIndexSpec<String> for S` | one `impl BlindIndexSpec for S { type Field = F; const BITS: u16 = …; type Query = str; … }` |
  | `derive_blind_index::<S, String, F>(&value, &keys)` | `S::derive_with(&value, &keys)` |
  | `blind_index_probes::<S, str, F>(query, &keys)` | `S::probes_with(query, &keys)` |
  | `verify_blind_index_candidate::<S, str>(query, candidate)` | `S::verify_candidate(query, candidate)` |

- **Breaking:** blind-index specifications are bound to one field (ADR-0001).
  `BlindIndexSpec` merges `BlindIndexMetadata` and the per-input
  `BlindIndexSpec<Input>`: it declares `type Field`, `const ID`,
  `const BITS: u16` (was `usize`), and `type Query`, and normalizes lookups with
  `normalize_query` and stored field values with `normalize_value`, so one spec
  no longer needs duplicate `str` and `String` impls, and an index can be
  computed from part of a value or combine several parts. The free functions
  `derive_blind_index`, `blind_index_probes`, and `verify_blind_index_candidate`
  are replaced by the provided methods `S::derive_with`, `S::probes_with`, and
  `S::verify_candidate`, which read the field from the spec; `S::probes` uses
  `GlobalKeyContext`. `Prepared::with_index_with`, `Prepared::with_index`,
  `Prepared::index`, and `RowPlanner::with_index_with` require
  `S: BlindIndexSpec<Field = F>`, so attaching another field's index is a type
  error. A spec previously used with several fields becomes one spec per field,
  or a spec generic over its field. Stored blind indexes are unchanged for the
  same field, index ID, precision, and normalization.

- **Breaking:** key providers receive the field they serve.
  `EncryptionKeyProvider::current_key(field)` and `key(field, id)`, and the
  same for `BlindIndexKeyProvider`, including `readable_keys(field)`. The local
  keyrings ignore the field.
- Add `Router`, a key provider that routes fields to providers by field ID for
  both encryption and blind-index roles. `Router::strict()` rejects unrouted
  fields with `Error::UnroutedField`; `Router::new(default)` falls back and
  reports fallback fields through `Router::falls_back`. A second route for one
  field ID fails with `Error::DuplicateRoute`. `Arc<P>` now implements both
  provider traits, so one router can hold providers of different types.

- Add the opt-in `serde` feature for explicit stored-byte serialization of
  ciphertext and blind indexes (not included in the published 0.5.0 crate).

- Fix `Postcard` silently ignoring bytes that follow a valid value. Trailing
  bytes now fail with `CodecErrorKind::Decoding`. Bytes produced by
  `Postcard::encode` are unaffected, but stored plaintext that carries extra
  bytes, such as padding read as unpadded, no longer decodes.

- Add task-oriented adoption guidance, document authority and version distinctions,
  shared feature/platform reference, and reproducible documentation link checks.

## 0.5.0

The following entries were shipped by 0.5.0 but retained an `Unreleased` heading
in that release's changelog. This heading correction does not introduce new API
or format changes.

- Add per-profile ISO/IEC 7816-4 padding with `NoPadding`, `PadToBlock`, and
  `PadToLength` policies. Manual `EncryptionProfile` implementations must add
  `type Padding`; `profile!` defaults to `NoPadding`, so existing stored data
  remains unchanged unless padding is explicitly enabled.
- Generalize the opt-in migration facility from plaintext adoption to legacy
  formats through `LegacyFormat`. `RowState::Plaintext` is now
  `RowState::Legacy`, `SweepReport::plaintext` is now `SweepReport::legacy`, and
  `MaybeEncrypted::is_plaintext` is now `MaybeEncrypted::is_legacy`.
- Defer decoding non-envelope bytes until a `MaybeEncrypted` decrypt call. A
  legacy codec error now occurs during decryption instead of `from_bytes` or
  SQLx `Decode`.
