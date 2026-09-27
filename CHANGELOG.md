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
  the automatic SQLx adapters) read the keys installed with `keys::install`; a field
  can no longer name its own key context. Stored field-bound ciphertext and blind
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
  context: `encrypt(F::ID, F::PADDING, plaintext, keys)`, `decrypt(F::ID, …)`,
  `reencrypt(F::ID, F::PADDING, …)`, and `needs_reencryption(F::ID, F::PADDING, …)`.

  Migrating from 0.5:

  | 0.5 | Now |
  | --- | --- |
  | `cryptbox::profile! { P: String { id: "…", name: "…", codec: Utf8 } }` | `struct P;` plus `impl Field for P { const ID: FieldId = field_id!("…"); const PADDING: Padding = Padding::NONE; type Value = String; type Codec = Utf8; }` |
  | `impl EncryptionProfile<String> for P { type Binding = FieldBound<Self>; … }` | `impl Field for P { type Value = String; … }` |
  | `type Binding = FieldBound<Other>;` | `const ID: FieldId = Other::ID;` |
  | `binding: unbound,` | re-encrypt existing data under a field ID first |
  | `type Padding = PadToBlock<16>;` | `const PADDING: Padding = Padding::block(16);` |
  | `type Keys = …;`, `Field::NAME` | remove; route the field in a `Router` and install it with `keys::install(Keys::new(router))` |
  | `Encrypted<String, P>`, `Encrypted::<_, P>` | `Encrypted<P>`, `Encrypted::<P>` |
  | `value.encrypt_with(&(), &keys)` | `value.encrypt_with(&keys)` |
  | `value.into()` into `Encrypted` | `Encrypted::new(value)` |
  | `encrypt::<FieldBound<F>>(bytes, &(), &keys)` | `encrypt(F::ID, F::PADDING, bytes, &keys)` |
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
  the installed keys. `Prepared::with_index_with`, `Prepared::with_index`,
  `Prepared::index`, and `RowPlanner::with_index_with` require
  `S: BlindIndexSpec<Field = F>`, so attaching another field's index is a type
  error. A spec previously used with several fields becomes one spec per field,
  or a spec generic over its field. Stored blind indexes are unchanged for the
  same field, index ID, precision, and normalization.
- Add the provided method `BlindIndexSpec::is_consistent_with(value, stored, keys)`,
  which checks a stored index against its decrypted value under the generation
  the index names, using the spec's own `normalize_value`, so audits check
  current and historical, exact, computed, and composite indexes alike. It
  returns `Ok(false)` for an inconsistent index and
  `Error::UnknownBlindIndexKey` for a generation the provider cannot resolve.

- **Breaking:** key providers receive the field they serve.
  `EncryptionKeyProvider::current_key(field)` and `key(field, id)`, and the
  same for `BlindIndexKeyProvider`, including `readable_keys(field)`. The local
  keyrings ignore the field.
- Add `Router`, a key provider that routes fields to providers by field ID for
  both encryption and blind-index roles. `Router::strict()` rejects unrouted
  fields with `Error::UnroutedField`, which aborts a sweep verification pass
  rather than counting rows as malformed; `Router::new(default)` falls back and
  reports fallback fields through `Router::falls_back`. A second route for one
  field ID fails with `Error::DuplicateRoute`. `Arc<P>` now implements both
  provider traits, so one router can hold providers of different types.
- **Breaking:** keys are supplied explicitly or installed once per process
  (ADR-0004). `cryptbox::keys::install(Keys)` replaces
  `GlobalKeyContext::install(GlobalProviders)` and returns
  `keys::AlreadyInstalled` (convertible to `Error::KeysAlreadyInstalled`) instead
  of replacing installed keys. `Keys::new(encryption).with_blind_indexes(indexes)`
  replaces `GlobalProviders` and is itself a provider for both roles, so it can be
  passed to every explicit form. Index operations on `Keys` without a
  blind-index provider fail with `Error::BlindIndexKeysNotConfigured`
  (`KeyProviderError::BlindIndexKeysNotConfigured`) instead of
  `KeyProviderUnavailable`. The implicit forms (`encrypt()`, `decrypt()`,
  `prepare()`, `with_index()`, `probes()`) are exactly their `_with` forms called
  with `keys::installed()`, and fail with `Error::KeysNotInstalled` (was
  `KeyProviderNotInitialized`) before installation. `KeyProviderError::NotInitialized`
  and `Error::KeyProviderAlreadyInitialized` are removed.
- **Breaking:** the automatic SQLx column is `Encrypted<F, K = GlobalKeys>`,
  whose column impls require `K: KeyContext`; the struct and its other methods
  do not bound `K`, so generic application types need not repeat the bound.
  `GlobalKeys` replaces `GlobalKeyContext` and reads the installed keys;
  implement `KeyContext::encryption_keys` over an application-owned static to
  give a column its own keys without installing the global. `KeyContext` no
  longer has `blind_index_keys`, and `encryption_keys` returns `Error`. `encrypt()` and `prepare()` exist only for the
  default `K`. The docs show a Clippy `disallowed_methods` configuration for
  teams that forbid the global.
- Add `Encrypted::with_key_context::<K>()`, which moves a value into another
  key context. Every decryption form, on `Ciphertext` and
  `migrate::MaybeEncrypted`, returns the default `Encrypted<F>`; convert it to
  bind the value through a column with application-owned keys.

- **Breaking:** new values are written as ciphertext format 2, which records in
  the authenticated envelope header whether the payload is padded (ADR-0002).
  Readers remove padding only when that flag is set, so `Field::PADDING` is
  write policy rather than persistent schema: a field can enable, disable, or
  resize padding without making stored values unreadable, and re-encryption
  rewrites them with the current policy. The header gains a flags byte, so
  envelopes are one byte longer (`W = P + 63`). `encrypt`, `reencrypt`, and
  `needs_reencryption` take the field's `Padding` after its ID
  (`encrypt(F::ID, F::PADDING, bytes, &keys)`); `decrypt` removes recorded
  padding. `needs_reencryption` also reports a format 1 envelope or a padding
  flag that disagrees with the policy, so a sweep converges both.
  `CiphertextInfo::padded` reports the flag. Format 1 stays readable, with
  padding interpreted by the field's current policy as before; sweep it to
  format 2 before changing a field's padding policy.

- Add the opt-in `derive` feature with `#[derive(Field)]`,
  `#[derive(BlindIndexSpec)]`, and `#[derive(Plaintext)]` from the new
  `cryptbox-derive` crate (ADR-0001). Each expands to exactly the manual impls
  and nothing else. IDs are UUID string literals validated at expansion, and
  padding and index precision are validated there too. A codec is never inferred:
  a field without `codec` uses its value type's `Plaintext` codec. A
  `#[derive(Plaintext)]` single-field tuple struct without `codec` stores
  exactly its inner value's bytes. Add `from_u128` to the identifier types,
  which the derives emit.

- **Breaking:** codecs and blind indexes name their persistent schema.
  `Codec` requires `const ID: &'static str`, a stable name for its byte
  representation: `"utf8"`, `"raw"`, `"json/1"`, and `"postcard/1"` for the
  crate's codecs. A derived transparent `Plaintext` codec reuses its inner
  codec's ID. `BlindIndexSpec` requires `const NORMALIZER: &'static str`, a
  name for its normalization rules, which `#[derive(BlindIndexSpec)]` takes
  from the new, required `normalizer = "…"` key. Neither is stored; the schema
  manifest reports both.
- Add schema guardrails for CI. `cryptbox::testing::assert_encoding::<F>(&value, hex)`
  pins a field's codec bytes to a committed fixture in both directions.
  `cryptbox::schema::Manifest` lists registered fields with their ID, value type,
  codec ID, and padding, and indexes with their ID, field, bits, and normalizer,
  for snapshot tests. Given `Keys`, it also reports each route.
  `Manifest::duplicates` reports IDs shared by several markers.
  `cryptbox::assert_unique_ids!` fails compilation when listed field (or
  `indexes:`) markers share an ID. Both provider traits gain
  `routing(field) -> Routing`, which defaults to `Routing::Direct`; `Router`, `Keys`,
  and `Arc<P>` report `Routed`, `Fallback`, or `Unrouted`. `Padding` implements
  `Display`.
- `Json` decodes every float to exactly the value that was encoded
  (`serde_json/float_roundtrip`). Before this, some stored floats were read back one ulp off.

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
