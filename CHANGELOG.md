# Changelog

## Unreleased

This release replaces profiles with seals and adds records. Values and blind
indexes stored by 0.5.0 are deliberately not readable: the envelope and the
blind index both move to format 2. Decisions are recorded in ADR-0001 to
ADR-0012.

### Seals

- **Breaking:** profiles are replaced by seals over the application's own value
  types (ADR-0001, ADR-0007). `Seal` declares `const ID: SealId` (`seal_id!`),
  `const PADDING`, `type Value`, `type Codec`, and `type Indexes`, the blind
  indexes declared over it. A seal is a marker over a value type, which several
  seals can share, or its own value. `profile!`, `EncryptionProfile`, `Field`,
  `Binding`, `FieldBound`, `Unbound`, `ProfileContext`, and the per-profile key
  context are removed.
- **Breaking:** only `String` and `Vec<u8>` and their `Secret` wrappers have a
  default codec, `Utf8` and `Raw`, permanently; a seal over any other value type
  names its codec. `Codec` requires `const ID: &'static str`, a stable name for
  its bytes, such as `"utf8"` or `"json/1"`.
- **Breaking:** `Padding` is a const value, `Padding::NONE`, `Padding::block(n)`,
  or `Padding::length(n)`, instead of `NoPadding`, `PadToBlock<N>`, and
  `PadToLength<N>`. The envelope records whether a value is padded, so padding
  is write policy: changing it keeps stored values readable, and a sweep rewrites
  them (ADR-0002).

### Sealed values

- **Breaking:** `Sealed<F>` replaces `Ciphertext<T, P>`, and the
  `Encrypted<T, P>` carrier is removed. `Sealed::seal(&value, &keys)`,
  `sealed.open(&keys)`, which returns the bare value, `Sealed::prepare`,
  `needs_reseal`, `reseal`, `reseal_across(&from_keys, &to_keys)`, and `key_id`
  take the keys to use. A value is bound to its seal ID: opened as another seal,
  it fails authentication.
- `Sealed<F, C = ()>` names the context a value is sealed in besides its seal ID
  (ADR-0012): `()` for a standalone value, or a `Context`, such as
  `InRecord<K>` for a record's field. `Sealed::seal_in(&value, &context, &keys)`,
  `open_in`, `prepare_in`, `reseal_in`, and `reseal_across_in` take the context's
  value, such as the record ID; `needs_reseal` serves every context. A seal
  knows nothing of where its values are stored. `Prepared` takes the same
  parameter.
- **Breaking:** the byte-level `encrypt`, `decrypt`, `reencrypt`, and
  `needs_reencryption` are removed; seal opaque bytes with a `Vec<u8>` seal.
  `is_ciphertext`, `inspect_ciphertext`, and `CiphertextInfo` stay, and
  `CiphertextInfo` reports `padded` and `context_fingerprint`.
- **Breaking:** the automatic SQLx column is `Plain<F, K = GlobalKeys>`. It
  serves seals without blind indexes, reads its keys from `K`, a `ColumnKeys`
  (was `KeyContext`), and converts with `Plain::with_column_keys`;
  `into_secret` is `into_inner`.
- `Prepared::sealed` (was `ciphertext`) and `Prepared::into_sealed`, and
  `BlindIndexRef::to_blind_index`, take owned values out of a preparation.

### Records

- Add `Record` and `#[derive(Record)]` for rows whose sealed fields are bound to
  their seal and to the row's record ID (ADR-0008, ADR-0010, ADR-0011). Every
  field has one role, `#[cryptbox(record_id)]`, `#[cryptbox(seal = "…")]` (with
  `codec`, `padding`, `name`, and `blind_index(…)`), or
  `#[cryptbox(plaintext)]`; a field without one fails the build. A record ID is
  a `Uuid` or `[u8; 16]`, an `i64`, or bytes. The derive generates the stored
  form, `Stored{Record}`, a seal per sealed field, a blind-index spec and an
  `Index` handle per blind index, such as `Customer::EMAIL_INDEX`, whose
  `probes` and `open_matching` run a lookup. `stored(…)` renames the stored form
  and forwards attributes to it, such as `derive(sqlx::FromRow)` or Serde's.
  Sealed fields are stored as `Sealed<F, InRecord<Id>>` and `Option<T>` fields
  as `Option<Sealed<F, InRecord<Id>>>`; `Record::Context` names the context.
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
  2. 0.5.0 indexes fail to parse with `Error::InvalidBlindIndex` instead of
  silently matching nothing; derive them again.

### Keys

- **Breaking:** keys are passed to each call or installed once per process
  (ADR-0004, ADR-0006, ADR-0010). `EncryptionKeyring` and `BlindIndexKeyring`
  (were `LocalEncryptionKeyring` and `LocalBlindIndexKeyring`) hold a current
  key and previous keys and reject duplicate key IDs; `Keys` pairs them, and
  `Keys::encryption` and `Keys::blind_indexes` read them.
  Operations take `EncryptionKeys`, `BlindIndexKeys`, or `RecordKeys`, and
  never read the installed keys; only the automatic SQLx column does.
  `keys::install(Keys)` replaces `GlobalKeyContext::install(GlobalProviders)` and
  returns `keys::AlreadyInstalled` instead of replacing the installed keys;
  `keys::installed()` returns them. The implicit `encrypt` and `decrypt` have no
  replacement: pass `keys::installed()?` to `seal` and `open`. The
  key provider traits, `KeyProviderError`, `GlobalKeyContext`, and
  `GlobalProviders` are removed. Choosing which keyring protects which values is
  application code; key IDs are generated UUIDs, never shared across keyrings.
- **Breaking:** key and keyring constructors return `KeyError`, which converts
  into `Error`. New errors: `KeysNotInstalled`, `KeysUnavailable` (was
  `KeyProviderUnavailable`), and `BlindIndexKeysNotConfigured`.

### Wire format

- **Breaking:** envelope format 2 has a fixed 31-byte header with a flags byte,
  which records padding, and an 8-byte context fingerprint (ADR-0002,
  ADR-0005). A value's context is its seal ID and, for a record's field, its
  record ID; reading a value of another kind of context reports
  `Error::ContextMismatch` before any key lookup. Format 1 envelopes, which
  0.5.0 wrote, report `UnsupportedFormatVersion(1)`.
- **Breaking:** `Error::UnsupportedSuite` carries the suite byte read from the
  header. `EXPERIMENTAL_XCHACHA20_POLY1305` and `SuiteId::new` are no longer
  public; `CiphertextInfo::suite_id` still reports the suite.

### Schema guardrails

- Add `testing::assert_encoding::<F>(&value, hex)`, which pins a seal's codec
  bytes to a committed fixture; `schema::Manifest`, which lists seals, blind
  indexes, and records with their IDs, codec IDs, padding, record ID kinds,
  context fingerprints, normalizers, and plaintext fields, for snapshot tests,
  and reports duplicate IDs, seals registered in several kinds of context
  (`Manifest::sealed::<F, C>()`), and seal IDs that fields of several records
  declare (`Duplicate::RecordField`); `assert_unique_ids!`, which fails compilation when
  listed markers share an ID; and `testing::assert_sealed_under`, which checks
  which keyring sealed a value.

### Derives and features

- Add the opt-in `derive` feature: `#[derive(Seal)]`, `#[derive(BlindIndexSpec)]`,
  and `#[derive(Record)]`, configured with `#[cryptbox(…)]`. Each expands to
  exactly the manual impls, plus a record's stored form and its fields' seals
  and index handles. IDs, padding, and index precision are validated when the
  macro expands, and `#[derive(Record)]` rejects a seal or index ID repeated
  within one record, whose fields' values could otherwise be swapped.
- Add the opt-in `serde` feature for stored bytes: `Sealed<F>` and
  `BlindIndex<S>` serialize as unpadded base64url text in human-readable
  formats and as bytes otherwise. `From<Sealed<F>> for Vec<u8>` and its
  `BlindIndex` equivalent serve ORMs that store bytes.
- `uuid` is a required dependency: the ID macros check their literal with
  `uuid::uuid!`. The `uuid` feature lets a record ID be a `uuid::Uuid`.

### Migration

- **Breaking:** the `migrate` module follows the new types.
  `MaybeEncrypted<F>` opens with `open(&keys)` and `open_legacy`, returns the
  bare value, and exposes `as_sealed`. `RowPlanner::with_index_with` is
  `with_index`, and `SweepError` is non-exhaustive.
  `RowPlanner<F, R = ()>` and `Sweep<F, R = ()>` take the type of a row's
  columns: `RowPlanner::new(&keys)` serves standalone values, and
  `RowPlanner::for_rows(&keys, |row| Ok(&row.id))` a record's field, whose
  context the record ID's type fixes. A seal no longer knows whether it is a
  record field's (ADR-0012), so `new` on a record field's seal, or `for_rows`
  with a record ID of another kind, builds, and every row reports
  `ContextMismatch`, which verification counts as malformed (#113).
  `SweepStore` gains `type Columns`, carried in `SweepRow::columns`.

### Fixes

- `Json` decodes every float to exactly the value that was encoded.
- `Postcard` rejects bytes that follow a valid value with
  `CodecErrorKind::Decoding` instead of ignoring them.
- The AEAD cipher zeroizes each derived encryption key and its ChaCha20 state
  on drop.
- A message of exactly 274,877,906,880 bytes fails with `MessageTooLong`
  instead of `Error::Internal`; suite 1 limits messages to 274,877,906,879
  bytes.

### Documentation

- New guides: records, choosing keyrings, shredding a tenant, integration with
  SQLx, Diesel, and Serde, and task-oriented adoption guidance, with the
  `records` and `tenant_field` examples.

### Migrating from 0.5

| 0.5 | Now |
| --- | --- |
| `cryptbox::profile! { P: String { id: "…", name: "…", codec: Utf8 } }` | `#[derive(cryptbox::Seal)] #[cryptbox(id = "…", value = String)] struct P;`, with the `derive` feature |
| `FieldId`, `field_id!`, `FieldId::from_uuid_literal("…")` | `SealId`, `seal_id!("…")` |
| `KeyId::from_uuid_literal("…")` and the other ID types' | `key_id!("…")`, `index_id!`, `index_key_id!` |
| `impl EncryptionProfile<String> for P { … }` | `impl Seal for P { const ID: SealId = seal_id!("…"); const PADDING: Padding = Padding::NONE; type Value = String; type Codec = Utf8; type Indexes = (); }` |
| `type Padding = PadToBlock<16>;` | `const PADDING: Padding = Padding::block(16);` |
| `Encrypted<String, P>`, `Ciphertext<String, P>` | `Sealed<P>` holds stored bytes; the value is a plain `String` |
| `Encrypted::new(v).encrypt_with(&(), &keys)` | `Sealed::<P>::seal(&v, &keys)` |
| `ciphertext.decrypt_with(&(), &keys)?.into_secret()` | `sealed.open(&keys)` |
| `reencrypt_with`, `needs_reencryption_with` | `reseal`, `needs_reseal` |
| `encrypt()`, `decrypt()` with `GlobalKeyContext::install(GlobalProviders::…)` | `seal(&v, keys::installed()?)`, `open(keys::installed()?)` after `keys::install(Keys::new(keyring))` |
| `LocalEncryptionKeyring`, `LocalBlindIndexKeyring` | `EncryptionKeyring`, `BlindIndexKeyring`, paired in `Keys` |
| `impl EncryptionKeyProvider for S` | resolve the keyring yourself and pass it |
| `Encrypted<T, P>` as an SQLx column | `Plain<P>` |
| `impl BlindIndexMetadata for S` plus `impl BlindIndexSpec<str> for S` | one `impl BlindIndexSpec for S { type Seal = P; const BITS: u16 = …; const NORMALIZER: &'static str = "…"; type Query = str; … }` |
| `derive_blind_index::<S, _, _>(&v, &keys)` | `BlindIndex::<S>::derive(&v, &keys)` |
| `blind_index_probes::<S, str, _>(q, &keys)` | `BlindIndex::<S>::probes(q, &keys)` |
| `verify_blind_index_candidate::<S, str>(q, c)` | `BlindIndex::<S>::verify_candidate(q, c)` |
| `RowPlanner::with_index_with` | `RowPlanner::with_index` |
| values stored by 0.5.0 | see [upgrading stored values](#upgrading-stored-values-from-05) |

### Upgrading stored values from 0.5

This release cannot read what 0.5.0 stored. Its values report
`UnsupportedFormatVersion(1)` and its indexes `InvalidBlindIndex`, and
`MaybeEncrypted::from_bytes`, `RowPlanner`, and the packaged sweeps report the
same errors rather than hand 0.5.0 envelopes to a `LegacyFormat` handler, so a
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
