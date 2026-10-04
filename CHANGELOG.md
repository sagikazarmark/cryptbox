# Changelog

## 0.6.0

This release replaces profiles with seals and adds records. Values and blind
indexes stored by 0.5.0 are deliberately not readable: the envelope and the
blind index both move to format 2. Both formats are now stable: later releases
read them, and a new construction would be a new suite ID or format version.
Decisions are recorded in ADR-0001 to ADR-0013.

### Seals

- **Breaking:** profiles are replaced by seals over the application's own value
  types (ADR-0001, ADR-0007). `Seal` declares `const ID: SealId` (`seal_id!`),
  `const PADDING`, `type Value`, and `type Codec`. A seal is a marker over a
  value type, which several seals can share, or its own value. `profile!`,
  `EncryptionProfile`, `Field`, `Binding`, `BindingDomain`, `FieldBound`,
  `Unbound`, `ProfileContext`, and the per-profile key context are removed.
- **Breaking:** `FieldId` and `field_id!` are `SealId` and `seal_id!`, and
  `from_uuid_literal` is removed from every ID type: declare IDs with the ID
  macros, such as `key_id!`, or `from_u128`, and parse them with `FromStr`.
- **Breaking:** only `String` and `Vec<u8>` and their `Secret` wrappers have a
  default codec, `Utf8` and `Raw`, permanently; a seal over any other value type
  names its codec. `Codec` requires `const ID: &'static str`, a stable name for
  its bytes, such as `"utf8"` or `"json/1"`.
- **Breaking:** `Padding` is a const value, `Padding::NONE`, `Padding::block(n)`,
  or `Padding::length(n)`, instead of `NoPadding`, `PadToBlock<N>`, and
  `PadToLength<N>`. The envelope records whether a value is padded, so padding
  is write policy: changing it keeps stored values readable, and a sweep rewrites
  them when padding is enabled or disabled, not when it is resized (ADR-0002).
  `Padding::length(n)` hides every length up to `n` bytes, padding to `n + 1`;
  `PadToLength<N>` padded to `N` and rejected values of `N` bytes (#86).

### Sealed values

- **Breaking:** `Sealed<F>` replaces `Ciphertext<T, P>`, and the
  `Encrypted<T, P>` carrier is removed. `Sealed::seal(&value, &keys)`,
  `sealed.open(&keys)`, which returns the bare value, `needs_reseal`, `reseal`,
  `reseal_across(&from_keys, &to_keys)`, and `key_id` take the keys to use. A
  value is bound to its seal ID: opened as another seal, it fails authentication.
- `Sealed<F, C = ()>` names the context a value is sealed in besides its seal ID
  (ADR-0012): `()` for a standalone value, or a `Context`, such as
  `InRecord<Id>` for a record's field. `Sealed::seal_in(&value, &context, &keys)`
  and `open_in` take the context's value, such as the record ID; `needs_reseal`
  serves every context. `C` is bounded by `ContextKind`, which only the library
  implements. A seal knows nothing of where its values are stored.
- **Breaking:** the byte-level `encrypt`, `decrypt`, `reencrypt`, and
  `needs_reencryption` are removed; seal opaque bytes with a `Vec<u8>` seal.
  `is_ciphertext`, `inspect_ciphertext`, `CiphertextInfo`,
  `inspect_blind_index`, and `BlindIndexInfo` move to the `cryptbox::envelope`
  module. `CiphertextInfo` reports `padded` and `context_fingerprint`, and
  `BlindIndexInfo::bits` returns a `u16`.
- **Breaking:** there is no automatic SQLx column that seals on encode and opens
  on decode (ADR-0013). Bind `Sealed<F>` and open it with the keys you pass in.
  `KeyContext` is removed.
- **Breaking:** `Prepared`, `prepare`, `prepare_with`, and `BlindIndexRef` are
  removed, with `Error::DuplicatePreparedIndex` and
  `Error::BlindIndexNotPrepared`. Seal the value with `Sealed::seal`, derive each
  index from the same value with `BlindIndex::derive`, and write them in one
  statement.

### Records

- Add `Record` and `#[derive(Record)]` for rows whose sealed fields are bound to
  their seal and to the row's record ID (ADR-0008, ADR-0010, ADR-0011). Every
  field has one role, `#[cryptbox(record_id)]`, `#[cryptbox(seal = "…")]` (with
  `codec`, `padding`, `name`, and `blind_index(…)`), or
  `#[cryptbox(plaintext)]`; a field without one fails the build. A record ID is
  a `Uuid` or `[u8; 16]`, or an `i64`, the types of the sealed
  `RecordIdType` trait. The derive generates the stored
  form, `Stored{Record}`, a seal per sealed field, a blind-index spec and an
  `Index` handle per blind index, such as `Customer::EMAIL_INDEX`, whose
  `probes` and `open_matching` run a lookup; a blind index is stored in the
  field's name with `_index`, such as `email_index`. `stored(…)` renames the
  stored form and forwards attributes to it, such as `derive(sqlx::FromRow)` or
  Serde's.
  Sealed fields are stored as `Sealed<F, InRecord<Id>>` and `Option<T>` fields
  as `Option<Sealed<F, InRecord<Id>>>`; `Record::Context` names the context.
  Only the derive implements `Record`.
- `Record::seal(&keys)` and `Record::open(stored, &keys)` seal and open a row,
  and `Record::open_expecting` checks a row before decrypting it, reporting
  `Error::UnexpectedRecord`. A field's value copied to another row or field
  fails to open, and a record field's value read as a standalone value reports
  `Error::ContextMismatch`. Plaintext columns, such as a tenant, are not
  authenticated: tenants are kept apart by keys.

### Blind indexes

- **Breaking:** a blind index is declared over one seal (ADR-0001).
  `BlindIndexSpec` merges `BlindIndexMetadata` and the per-input
  `BlindIndexSpec<Input>`: it declares `type Seal`, `const ID`, `const BITS: u16`
  (was `usize`), `const NORMALIZER: &'static str`, a name for its normalization
  rules, and `type Query`, and normalizes queries and stored values separately,
  so an index can project part of a value. `derive_blind_index`,
  `blind_index_probes`, and `verify_blind_index_candidate` are replaced by
  `BlindIndex::<S>::derive`, `BlindIndex::<S>::probes`, and
  `BlindIndex::<S>::verify_candidate`, which a spec cannot override.
- Add `BlindIndex::is_consistent_with`, which checks a stored index against
  its decrypted value under the key generation the index names.
- **Breaking:** blind indexes are derived under their seal ID and move to format
  2. 0.5.0 indexes fail to parse with `Error::UnsupportedBlindIndexVersion(1)`
  instead of silently matching nothing; derive them again.
- **Breaking:** `Error::BlindIndexNormalizationFailed` carries the
  `BlindIndexError` the normalizer returned.

### Keys

- **Breaking:** keys are passed to each call (ADR-0006, ADR-0010, ADR-0013).
  `EncryptionKeyring` and `BlindIndexKeyring` (were `LocalEncryptionKeyring` and
  `LocalBlindIndexKeyring`) hold a current key and previous keys and reject
  duplicate key IDs; `Keys` pairs them, and `Keys::encryption` and
  `Keys::blind_indexes` read them.
  Operations take `EncryptionKeys`, `BlindIndexKeys`, or `RecordKeys`, and
  nothing reads a global. The implicit `encrypt` and `decrypt` have no
  replacement: load the keys at startup and pass them to `seal` and `open`. The
  key provider traits, `KeyProviderError`, `GlobalKeyContext`, and
  `GlobalProviders` are removed. Choosing which keyring protects which values is
  application code; key IDs are generated UUIDs, never shared across keyrings.
- **Breaking:** `Error::KeyProviderUnavailable`, `KeyProviderNotInitialized`,
  and `KeyProviderAlreadyInitialized` are removed: the library never looks keys
  up or installs them, so resolution errors are the application's. A blind-index
  operation given `Keys` without a blind-index keyring reports the new
  `Error::BlindIndexKeysNotConfigured`.

### Wire format

- **Breaking:** envelope format 2 has a fixed 31-byte header with a flags byte,
  which records padding, and an 8-byte context fingerprint (ADR-0002,
  ADR-0005). A value's context is its seal ID and, for a record's field, its
  record ID; reading a value of another kind of context reports
  `Error::ContextMismatch` before any key lookup. Format 1 envelopes, which
  0.5.0 wrote, report `UnsupportedFormatVersion(1)`.
- **Breaking:** `Error::UnsupportedSuite` carries the suite byte read from the
  header. `SuiteId` and `EXPERIMENTAL_XCHACHA20_POLY1305` are no longer public;
  `CiphertextInfo::suite_id` reports the suite as a `u8`.
- **Breaking:** an envelope with a reserved flag bit set reports
  `Error::UnsupportedFlags`, carrying the flags byte, and a blind index of
  another format version `Error::UnsupportedBlindIndexVersion`, instead of
  `InvalidEnvelope` and `InvalidBlindIndex`, so data a later release writes is
  reported as unsupported rather than malformed (#117). An envelope's format
  version is checked before its length, so a later format with a shorter header
  is unsupported too; a blind index, which has no magic, needs a full header
  first.
- A context is its seal ID, a part count, and each part's kind code and
  length-prefixed value; the context fingerprint is the first 8 bytes of SHA-256
  over the label `cryptbox/context-fingerprint/v1\0`, the part count, and the
  parts' kind codes. A context has exactly one encoding.
- The text form of envelopes and blind indexes in human-readable Serde formats
  is defined in the [wire format](docs/wire-format.md): unpadded base64url,
  decoded strictly.
- The blind-index test vectors include full-width (256-bit) and byte-aligned
  (64-bit) vectors.
- `cargo-fuzz` targets cover the envelope and blind-index parsers, and sealing
  and deriving under mutation; CI runs them for a bounded time (#11).

### Schema guardrails

- Add `testing::assert_encoding::<F>(&value, hex)`, which pins a seal's codec
  bytes to a committed fixture; `schema::Manifest`, which lists seals, blind
  indexes, and records with their IDs, codec IDs, padding, record ID kinds,
  context fingerprints, normalizers, and plaintext fields, for snapshot tests,
  and reports duplicate IDs, seals registered in several kinds of context
  (`Manifest::sealed::<F, C>()`), and seal IDs that fields of several records
  declare (`Duplicate::RecordField`); `assert_unique_ids!`, which fails
  compilation when listed markers share an ID, declare the nil UUID, or name an
  unversioned normalizer; and `testing::assert_sealed_under`, which checks
  which keyring sealed a value.

### Derives and features

- Add the opt-in `derive` feature: `#[derive(Seal)]`, `#[derive(BlindIndexSpec)]`,
  and `#[derive(Record)]`, configured with `#[cryptbox(…)]`. Each expands to
  exactly the manual impls, plus a record's stored form and its fields' seals
  and index handles. IDs, padding, and index precision are validated when the
  macro expands, and `#[derive(Record)]` rejects a seal or index ID repeated
  within one record, whose fields' values could otherwise be swapped. They
  reject the nil UUID, a normalizer name without a version, such as `"email"`
  instead of `"email/1"` (#77), and generic types; `Seal` rejects unions, and
  `BlindIndexSpec` anything but a struct (#82). The ID macros reject the nil
  UUID too, and so do `from_u128` and parsing an ID with `FromStr`;
  `from_bytes` does not check, since stored IDs are read through it.
- Add the opt-in `serde` feature for stored bytes: `Sealed<F>` and
  `BlindIndex<S>` serialize as unpadded base64url text in human-readable
  formats and as bytes otherwise. The `json` feature enables `serde`.
  `From<Sealed<F>> for Vec<u8>` and its `BlindIndex` equivalent serve ORMs that
  store bytes.
- `uuid` is a required dependency: the ID macros check their literal with
  `uuid::uuid!`, and a record ID may be a `uuid::Uuid`.
- **Breaking:** the `postcard` feature and the `Postcard` codec are removed.
  Write a `Codec` for a positional format your application needs.

### Migration

- **Breaking:** the `migrate` module follows the new types.
  `MaybeEncrypted<F>` is `MaybeSealed<F>`, opens with `open(&keys)` and
  `open_legacy`, returns the bare value, and exposes `as_sealed`.
  `RowPlanner::with_index_with` is `with_index`, and `SweepError` is
  non-exhaustive.
  `RowPlanner<F, R = ()>` and `Sweep<F, R = ()>` take the type of a row's
  columns: `RowPlanner::new(&keys)` serves standalone values, and
  `RowPlanner::for_rows(&keys, |row| Ok(&row.id))` a record's field, whose
  context the record ID's type fixes. A seal no longer knows whether it is a
  record field's (ADR-0012), so `new` on a record field's seal, or `for_rows`
  with a record ID of another kind, builds, and every row reports
  `ContextMismatch`, which verification counts as malformed (#113).
  `SweepStore` gains `type Columns`, carried in `SweepRow::columns`.
- **Breaking:** a sweep runs with `Sweep::run` and is verified with
  `Sweep::verify`. `process_batch`, `run_batch`, `verify_batch`, `BatchOutcome`,
  and `SweepReport::merge` are removed; an orchestrator that steps a sweep itself
  uses `SweepStore` and `RowPlanner::plan_row`. `SweepRow` is non-exhaustive:
  build it with `SweepRow::new`.
- **Breaking:** `MaybeSealed::from_plaintext` is removed; wrap bytes known to be
  legacy with `from_legacy_bytes`.
- **Breaking:** `LegacyFormat` requires `Send + Sync`, so `RowPlanner`, `Sweep`,
  and the future of `Sweep::run` are `Send` and a sweep can run on a spawned
  task. In 0.5.0 none of them was.

### Fixes

- `SqliteSweepStore` sweeps legacy values stored as TEXT. Its guarded update
  compared them with BLOB bytes, which never match, so every such row counted as
  a conflict and the checkpoint moved past it. A NULL in a swept column now
  stops the sweep with a column decode error, as `PostgresSweepStore` does,
  instead of reading as empty bytes and conflicting the same way.
- `Json` decodes every float to exactly the value that was encoded.
- The AEAD cipher zeroizes each derived encryption key and its ChaCha20 state
  on drop.
- A message of exactly 274,877,906,880 bytes fails with `MessageTooLong`
  instead of `Error::Internal`; suite 1 limits messages to 274,877,906,879
  bytes.

### Documentation

- The guides are consolidated into a [guide](docs/guide.md), covering records,
  choosing keyrings, schema, storage, and testing, and
  [operations](docs/operations.md), covering rotation, sweeps, migration, and
  shredding, with the `records` and `tenant_seal` examples.
- `cryptbox-derive` has a README.

### Migrating from 0.5

| 0.5 | Now |
| --- | --- |
| `cryptbox::profile! { P: String { id: "…", name: "…", codec: Utf8 } }` | `#[derive(cryptbox::Seal)] #[cryptbox(id = "…", value = String)] struct P;`, with the `derive` feature |
| `FieldId`, `field_id!`, `FieldId::from_uuid_literal("…")` | `SealId`, `seal_id!("…")` |
| `KeyId::from_uuid_literal("…")` and the other ID types' | `key_id!("…")`, `index_id!`, `index_key_id!` |
| `impl EncryptionProfile<String> for P { … }` | `impl Seal for P { const ID: SealId = seal_id!("…"); const PADDING: Padding = Padding::NONE; type Value = String; type Codec = Utf8; }` |
| `type Padding = PadToBlock<16>;` | `const PADDING: Padding = Padding::block(16);` |
| `Encrypted<String, P>`, `Ciphertext<String, P>` | `Sealed<P>` holds stored bytes; the value is a plain `String` |
| `Encrypted::new(v).encrypt_with(&(), &keys)` | `Sealed::<P>::seal(&v, &keys)` |
| `ciphertext.decrypt_with(&(), &keys)?.into_secret()` | `sealed.open(&keys)` |
| `reencrypt_with`, `needs_reencryption_with` | `reseal`, `needs_reseal` |
| `encrypt()`, `decrypt()` with `GlobalKeyContext::install(GlobalProviders::…)` | `seal(&v, &keys)`, `open(&keys)`, with `Keys::new(keyring)` loaded at startup and passed in |
| `LocalEncryptionKeyring`, `LocalBlindIndexKeyring` | `EncryptionKeyring`, `BlindIndexKeyring`, paired in `Keys` |
| `impl EncryptionKeyProvider for S` | resolve the keyring yourself and pass it |
| `Encrypted<T, P>` as an SQLx column | `Sealed<P>`, opened with `open(&keys)` |
| `impl BlindIndexMetadata for S` plus `impl BlindIndexSpec<str> for S` | one `impl BlindIndexSpec for S { type Seal = P; const BITS: u16 = …; const NORMALIZER: &'static str = "…"; type Query = str; … }` |
| `derive_blind_index::<S, _, _>(&v, &keys)` | `BlindIndex::<S>::derive(&v, &keys)` |
| `blind_index_probes::<S, str, _>(q, &keys)` | `BlindIndex::<S>::probes(q, &keys)` |
| `verify_blind_index_candidate::<S, str>(q, c)` | `BlindIndex::<S>::verify_candidate(q, c)` |
| `encrypted.prepare()?.with_index::<S>()?`, then `ciphertext()` and `index::<S>()` | `Sealed::<P>::seal(&v, &keys)` and `BlindIndex::<S>::derive(&v, &keys)` |
| `RowPlanner::with_index_with` | `RowPlanner::with_index` |
| `Sweep::run_batch`, `process_batch`, `verify_batch` | `Sweep::run`, `Sweep::verify` |
| values stored by 0.5.0 | see [upgrading stored values](#upgrading-stored-values-from-05) |

### Upgrading stored values from 0.5

This release cannot read what 0.5.0 stored. Its values report
`UnsupportedFormatVersion(1)` and its indexes
`UnsupportedBlindIndexVersion(1)`, and `MaybeSealed::from_bytes`,
`RowPlanner`, and the packaged sweeps report the same errors rather than hand 0.5.0 envelopes to a `LegacyFormat` handler, so a
sweep cannot drive this upgrade. Rewrite stored values with a program that
depends on both versions, adding 0.5.0 under another name:

```toml
cryptbox05 = { package = "cryptbox", version = "=0.5.0" }
```

Load the same key material into both versions' keyrings. For each row, open
every value with 0.5.0 (`decrypt_with`), seal it again with this release
(`Sealed::seal`, or `Record::seal` for a record), derive its blind indexes again,
and write them in one statement. Until every row is rewritten, read with this
release and fall back to 0.5.0 on `UnsupportedFormatVersion(1)`, and look up
blind indexes in both formats.

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
