# Integration design and trade-offs

After a first round trip, the main design questions are where encryption happens,
which policy remains stable with stored data, and how keys reach each operation.
This page explains those choices and their consequences. It builds on
[how CryptBox works](concepts.md); for a runnable next step, follow the
[durable SQLite example](../examples/sqlite/README.md).

## Persistent schema

Encrypted storage is not entirely self-describing. An envelope identifies its
format, suite, encryption-key generation, and whether its payload is padded, but
the application supplies the expected seal ID, binding, and codec. An
envelope also carries a fingerprint of its binding declaration, which only names a
mismatch. A blind index
additionally depends on a logical index ID and normalization rule that are not
stored with it.

These choices form persistent schema just as database column types do:

| Choice | Why it must remain compatible |
| --- | --- |
| Value type and codec | Authenticated bytes still need to decode into the intended application value. A different codec can decode existing bytes into a wrong value without an error. |
| Seal ID | Every value is bound to its seal ID; a different ID fails authentication. |
| Binding declaration and record kind | Every value is bound to the kinds of its bound values, and to its record when the seal binds one; a different declaration reports `BindingMismatch`. |
| Index ID and normalization | Writers, queries, and candidate comparisons must agree on the meaning of equality. |
| Index precision | Stored indexes and probes must use the same retained bit count. |

Rust type names are not cryptographic identities. Renaming
a type does not change its seal ID; generating a new ID does. Changing these
policies requires a compatibility and migration plan, not just a new deployment.
The [legacy migration guide](legacy-migration.md) covers adopting CryptBox over
plaintext or another encryption solution; it is not a general seal-schema
migration procedure.

Only four value types have a default codec: `Utf8` for `String` and
`Secret<String>`, `Raw` for `Vec<u8>` and `Secret<Vec<u8>>`. These mappings are
permanent and no feature changes them. A seal over any other value type,
including a Serde type, names its codec, which is persistent schema too; a
`transparent` seal stores its single field with that field's codec. Two seals over one value type
(`HomeAddress` and `BillingAddress` over `Address`) have separate seal IDs, so
their ciphertext cannot be swapped.

Serde codecs make the value type's Serde representation persistent schema.
A serde attribute change on a value type, such as adding `rename_all`,
`rename`, or `tag`, changes the stored bytes of every seal that uses that
type. `Postcard` is positional: it stores no field or variant names. Reordering
struct fields or enum variants, or changing an integer type, can decode existing
bytes into wrong values without an error. `Json` stores names, so a renamed
field fails to decode or silently takes its default.

Normalizers are persistent schema too. A blind index stores only the keyed
projection of normalized bytes, so a normalizer that now trims, folds case, or
projects differently silently stops matching existing indexes. Name its rules
with `BlindIndexSpec::NORMALIZER`, such as `"email/1"`, and bump the version
with every change.

### Guarding the schema in CI

Stored bytes do not describe this schema, so check it in tests:

- **Golden bytes.** `cryptbox::testing::assert_encoding::<F>(&value, "…hex…")`
  checks that a seal still encodes a representative value to the committed bytes
  and decodes them back. Commit one fixture per seal, and treat it as essential
  for `Json` and `Postcard` seals, whose bytes follow the value type's
  derives and attributes. A failure means stored values would change; plan a
  migration or revert.
- **Schema manifest.** `cryptbox::schema::Manifest` lists each registered seal
  (ID, codec ID, padding, whether it binds a record, and the binding
  fingerprint with each bound value's part ID and kind), index (ID, seal, bits,
  normalizer, and partition), and record (its seals, record ID field, bound
  fields, plaintext fields, and open legacy windows by name, so a field that
  should have been sealed shows up). Compare the `Display` output with a
  committed snapshot, and
  assert that `duplicates()` is empty. A snapshot diff needs review: for
  example, a codec ID, normalizer, or binding change needs a migration.
- **Unique IDs.** `cryptbox::assert_unique_ids!(HomeAddress, BillingAddress)`
  fails compilation when listed seals share a seal ID, and
  `assert_unique_ids!(indexes: EmailLookup, EmailDomain)` does the same for
  index IDs. It is a constant check, so it works with manual impls.

The [custom-field example](../examples/custom_field/main.rs)'s
`stored_bytes_and_schema_match_their_committed_fixtures` test runs the golden-bytes
and manifest checks.
The manifest names IDs, never Rust types, so its output is the same on every
toolchain and does not change when a marker is renamed or moved. A record's
field names are the one exception: a field stored as it is has no ID.

The library cannot see which keyring an application chooses. Test the choice
with `cryptbox::testing::assert_sealed_under::<F>(&sealed, &keyring)`, which
fails when a value sealed with the keys the application resolved names a key
that the expected keyring does not hold. A value sealed under the wrong keyring
otherwise seals and opens without error, and outlives the destruction of the
keys that should have protected it.

Padding is not persistent schema. The envelope records, under authentication,
whether its payload is padded, and readers remove padding only when that flag is
set. A seal's padding policy describes how new values are written: enabling,
disabling, or resizing it keeps existing values readable, and a
[re-encryption sweep](reencryption-sweep.md) rewrites them with the current
policy. Current padding parameters also do not impose a limit on historical
reads. See the [size and padding contracts](wire-format.md#plaintext-padding).

## Storage boundaries

The choice between explicit operations and automatic adapters determines where
keys are needed and where plaintext becomes available:

| Approach | Behavior and consequence |
| --- | --- |
| Explicit sealing or preparation | Produce a sealed value before calling storage. Key failures happen at that explicit step; the stored representation can then cross a database or serialization boundary. |
| Read as a stored form or `Sealed<F>` | SQLx decoding or Serde deserialization checks structure without keys. The application chooses when to open it: a record reads its bound values from the row. Useful when only some loaded values need plaintext. |
| Automatic SQLx `Plain<F>` | The adapter seals on encode and opens on decode. It reads keys from its `ColumnKeys` type `K`: the installed keys by default, so ordinary database conversion needs `keys::install`, or an application-owned static named as `Plain<F, K>`. |

The automatic `Plain<F>` column serves only seals without bound values, a
record, or blind indexes: a column decoder sees neither the row nor its bound
values, and would not write index columns. Seal values of bound and indexed seals explicitly. Explicit operations
are useful when dependencies and plaintext access should be visible at the call
site. Automatic adapters are useful when
encryption belongs consistently at the database boundary.

The application owns database schemas, transactions, query construction, and
concurrency policy. SQLx features do not choose the application's async runtime
or TLS configuration. Serde handles stored bytes only and supplies neither
encryption nor atomic persistence. See [features and platforms](features.md) for
exact availability and configuration requirements.

Try [records with SQLx](../examples/records/README.md),
[explicit SQLite storage](../examples/sqlite/README.md), the
[automatic-adapter example](testing.md#automatic-adapters), or
[stored-value serialization](../examples/stored_values/README.md).

## Records, ORMs, and serde

A record's stored form is an ordinary struct, so a database layer or a serde
format reads and writes it like any other; sealing and opening stay explicit
calls, never hooks of the storage layer. `#[cryptbox(stored(…))]` forwards
attributes to it, at the record or at a field:

| Layer | Stored form |
| --- | --- |
| SQLx | `stored(derive(sqlx::FromRow))`. `Sealed<F>` and `BlindIndex<S>` are `BLOB` or `bytea`; a bound ID newtype derives `sqlx::Type` with `#[sqlx(transparent)]`. |
| Diesel | `stored(derive(Queryable, Selectable, Insertable), diesel(table_name = …))`, and `stored(diesel(serialize_as = Vec<u8>, deserialize_as = Vec<u8>))` on each sealed field and index column, through `From<Sealed<F>> for Vec<u8>` and `TryFrom<Vec<u8>>`. A bound ID newtype needs Diesel's usual newtype impls. |
| serde | `stored(derive(Serialize, Deserialize))`. Human-readable formats, such as JSON, write sealed values and blind indexes as unpadded base64url text and read text or byte sequences; binary formats write bytes. |

The stored form's field order follows the record's, each index column after its
field, so a positional format, such as `Postcard`, makes it persistent schema:
append fields rather than reordering them. An `Option<T>` sealed field stores
`Option<Sealed<F>>` and an optional index column. The
[records example](../examples/records/README.md) runs SQLx and serde messages.

## Keyrings

A **keyring** holds one current key generation and the previous generations
that stored data still needs: `EncryptionKeyring` for values and
`BlindIndexKeyring` for blind indexes. `Keys` pairs an encryption keyring with an
optional blind-index keyring. The **installed keys** back the process-wide forms,
and a **`ColumnKeys`** type selects the keys of an automatic SQLx column.

Which keyring protects which values is the decision with the most silent
failure modes; [choosing keyrings](choosing-keyrings.md) covers it in full, and
[shredding a tenant](shredding.md) covers what destroying one tenant's keys does.

Operations take the keys to use. Explicit `Sealed::seal`, `open`, and `prepare`
take an `EncryptionKeyring` or `Keys`; `with_index_with` and `probes_with` a
`BlindIndexKeyring` or `Keys`; and a record's `seal` an `EncryptionKeyring`, or
`Keys` when it has blind indexes. They never read the installed keys, so each
test or application component owns its dependencies.

Choosing which keyring protects which values is application code. Pass the
payments keyring when sealing an IBAN and the general keyring when sealing an
email, or an org's keyring for its rows, resolved in one function of your own. Opening
with the wrong keyring fails loudly with `Error::UnknownEncryptionKey`, as long
as key IDs are generated UUIDs, unique within a keyring, and never shared across
keyrings. Sealing with the wrong keyring succeeds silently, so test the choice:
[choosing keyrings](choosing-keyrings.md) lists the failure modes, the key-ID
rules, and how to record and test custody.

The process-wide forms (`Sealed::seal_global`, `open_global`, `with_index()`,
`probes()`) are the explicit forms called with `keys::installed()`. Like the
automatic column, `seal_global` and `open_global` serve only seals without
bound values or a record.
`keys::install(keys)` sets the installed keys once per process, from the binary
entry point; a second call returns `AlreadyInstalled` and never replaces them.
Before installation the process-wide forms return `Error::KeysNotInstalled`: there is
no default and no panic. There are no thread- or task-scoped keys, because work
spawned outside a scope would silently use other keys
([ADR-0004](adr/0004-key-supply-global-and-explicit.md)).

The automatic SQLx column `Plain<F, K>` takes its keys as a type,
because SQLx decoding receives no context. The default `K`, `GlobalKeys`, reads
the installed keys. Implement `ColumnKeys` over an application-owned static
`Keys` to use a second keyring or a test fixture without the global.
`Plain::with_column_keys::<K>()` moves a value into another column type without
resealing it. A seal does not choose its keys.

Teams that forbid the global can deny `keys::install` and the process-wide forms with
Clippy's `disallowed_methods`, using
[this `clippy.toml`](snippets/clippy-no-global-keys.toml). Denying `install` alone
keeps the installed keys empty, so process-wide calls fail at run time; denying
the process-wide forms also reports them at lint time. With the `migrate` feature,
also deny `MaybeEncrypted::open_global` and `MaybeEncrypted::open_global_legacy`.

Resolving keys is synchronous. Applications load secrets from their chosen
source and build keyrings locally; CryptBox does not distribute secrets or
refresh remote key-management state. Startup snapshots are simple, but changing
their source files does not refresh a running process. Refreshing keys owns
synchronization, availability, and consistent generation selection, and returns
`Error::KeysUnavailable` when its keys are not loaded.

For durable data, the public generation ID and root material are one immutable
pair. Reload that exact pair after restarts and retain readable generations while
stored data needs them. Replacing a missing key with a newly generated one cannot
recover existing ciphertext. Encryption and blind-index roles use independently
generated roots; encryption-only applications need no index roots.

The [SQLite example](../examples/sqlite/README.md#2-provision-the-demonstration-key-once) shows
a single durable encryption generation. The [searchable example](../examples/searchable/README.md#provision-durable-key-generations-once)
adds independent index generations. For keys the application refreshes, see
[their contract](../examples/custom_field/README.md#implementor-obligations); for
changing a serving keyset, see [key lifecycle](key-rotation.md).

## Search and atomic writes

The [introductory search flow](concepts.md#search-uses-a-separate-representation)
explains normalization, probes, and candidate verification. Integration adds two
design decisions: how much precision to retain and how to keep the stored
projection consistent with its ciphertext.

Precision controls how many digest bits are retained. Fewer bits increase false
candidates and obscure equality more, without eliminating equality or frequency
leakage. The right policy depends on the data distribution and candidate workload;
low-cardinality or highly skewed sensitive values can remain revealing. A blind
index cannot enforce uniqueness.

Preparation supplies the representations for a write; it does not supply the
transaction. A single SQL statement can update ciphertext and its indexes together.
Multi-statement writes require an application-owned transaction, and concurrent
updates need whatever conflict policy the application normally uses. Automatic
sealing of one column would not maintain another column, so `Plain<F>` rejects a
seal that declares blind indexes.

A blind index is domain-separated by its seal ID and by the
[index binding](wire-format.md#index-binding): the values of its partition, all
of its seal's bound values except those it spans. Equal values in different
partitions therefore have different index bytes, and a query supplies the
partition. The bound values an index spans, such as the workspaces of an
org-wide index, and the record do not participate, because a query cannot know
them, so equal values in two workspaces of one org share index bytes. Choose
partitions with that in mind; see
[bindings](bindings.md#partition-each-blind-index).

Search availability also depends on retaining all readable index-key generations.
An application can decrypt a row successfully yet omit it from lookup if the
corresponding index generation is unavailable. Checking candidate plaintext and
checking stored-index consistency are separate tasks; see
[what each check establishes](security.md#what-each-check-establishes).

The [searchable storage example](../examples/searchable/README.md) demonstrates the complete write
and lookup path together. Adding search to existing data also requires a plan to
populate and verify indexes before relying on index-only queries.

## Plaintext lifetime and extension points

Application values remain plaintext in memory. Borrowing them for sealing or
preparation does not erase them, and decoded values have their own lifetimes.
`Secret<T>` can zeroize a compatible owned value on drop; it does not erase other
copies. The [ownership reference](ownership.md) defines exact behavior by type
and buffer.

Seals, value types, codecs, normalizers, and bound ID types are extensible; padding policies are a closed set of built-in const policies. A
codec or normalizer cannot add bound-value or record authentication: that comes
from the seal's [binding](bindings.md). The
[custom-field example](../examples/custom_field/README.md)
shows a zeroizing value, codec, normalizer, and refreshed keys working together.

## From design to a working application

- [Bindings](bindings.md) covers bound values, records, blind-index partitions,
  and where each bound value must come from.
- [Choosing keyrings](choosing-keyrings.md) covers custody, key-ID rules, and
  testing which keyring protects which seal.
- [Testing and diagnostics](testing.md) covers key isolation and sanitized failures.
- [Legacy adoption](legacy-migration.md) addresses existing plaintext or foreign
  ciphertext; review its prerequisites before enabling new encrypted writes.
- [Security](security.md) describes the trust boundary and application responsibilities.
- [Key lifecycle](key-rotation.md) and [maintenance sweeps](reencryption-sweep.md)
  cover rollout and later rewriting. Rotation and schema evolution are separate changes.
