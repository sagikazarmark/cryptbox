# Changelog

## Unreleased

- **Breaking:** every profile is bound to its field. `EncryptionProfile` now
  extends `Field` and declares its plaintext type as `type Value`, so wrapper
  types take only the profile: `Encrypted<UserEmail>`,
  `Ciphertext<UserEmail>`, `MaybeEncrypted<UserEmail>`, `Prepared<'_, UserEmail>`,
  `RowPlanner<'_, UserEmail>`, and `Sweep<'_, UserEmail>`. `Binding`, `Unbound`,
  `FieldBound`, and `ProfileContext` are removed, and the unit `&()` binding
  context argument is dropped from every `*_with` method and from
  `RowPlanner::new`. Stored field-bound ciphertext and blind indexes are
  unchanged and need no data migration. Binding tag `00` is reserved, so data
  written with `Unbound` is no longer readable.
- **Breaking:** `Encrypted::new` accepts `impl Into<Profile::Value>` and is no
  longer `const`. The `From<T>` implementation for `Encrypted` is removed; use
  `Encrypted::new`.
- **Breaking:** low-level primitives take the field as a type parameter instead
  of a binding and context: `encrypt::<F>(plaintext, keys)`,
  `decrypt::<F>`, `reencrypt::<F>`, `derive_blind_index::<Spec, Input, F>`, and
  `blind_index_probes::<Spec, Input, F>`.
- `profile!` requires only `id`. `name` defaults to the marker identifier,
  `codec` defaults through the sealed `DefaultCodec` trait (`Utf8` for `String`,
  `Raw` for `Vec<u8>`, permanently), and optional keys may appear in any order.
  The `binding` key is removed. Other value types must name their codec.

  Migrating from 0.5:

  | 0.5 | Now |
  | --- | --- |
  | `binding: field_bound,` in `profile!` | remove the line |
  | `binding: unbound,` in `profile!` | remove the line; re-encrypt existing data under the field ID first |
  | `impl EncryptionProfile<String> for P { type Binding = FieldBound<Self>; … }` | `impl EncryptionProfile for P { type Value = String; … }` |
  | `type Binding = FieldBound<Other>;` | implement `Field` for the profile with `Other::ID` |
  | `Encrypted<String, P>`, `Encrypted::<_, P>` | `Encrypted<P>`, `Encrypted::<P>` |
  | `value.encrypt_with(&(), &keys)` | `value.encrypt_with(&keys)` |
  | `value.into()` into `Encrypted` | `Encrypted::new(value)` |
  | `encrypt::<FieldBound<F>>(bytes, &(), &keys)` | `encrypt::<F>(bytes, &keys)` |

- **Breaking:** key providers receive the field they serve.
  `EncryptionKeyProvider::current_key(field)` and `key(field, id)`, and the
  same for `BlindIndexKeyProvider`, including `readable_keys(field)`. The local
  keyrings ignore the field. `needs_reencryption` takes the field as a type
  parameter: `needs_reencryption::<F>(bytes, keys)`.
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
