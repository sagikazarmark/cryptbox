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
| Binding declaration and record kind | Every value is bound to its binding's part IDs, kinds, and keys view, and to its record when the seal binds one; a different declaration reports `BindingMismatch`. |
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
  (ID, codec ID, padding, whether it binds a record, the binding
  fingerprint and parts with their kinds and roles in the keys view, and the
  shred unit) and index (ID, seal, bits, normalizer, and index scope). `Manifest::custody::<F>("…")` adds a
  custody label to a seal, such as `"payments KMS, one key per org"`, so
  reviewers and auditors see which keys the application passes for it.
  Compare the `Display` output with a committed snapshot, and
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
toolchain and does not change when a marker is renamed or moved.

A custody label is declarative: the library cannot see which keyring an
application chooses. Test the choice itself with
`cryptbox::testing::assert_sealed_under::<F>(&sealed, &keyring)`, which fails
when a value sealed through the application's key source names a key that the
expected keyring does not hold. A value sealed under the wrong keyring
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
| Read as `Sealed<F>` | SQLx decoding or Serde deserialization checks structure without keys. The application chooses when to open it, with the binding values of the row. Useful when only some loaded values need plaintext. |
| Automatic SQLx `Plain<F>` | The adapter seals on encode and opens on decode. It reads keys from its `ColumnKeys` type `K`: the installed keys by default, so ordinary database conversion needs `keys::install`, or an application-owned static named as `Plain<F, K>`. |

The automatic `Plain<F>` column serves only unscoped seals without a record or
blind indexes: a column decoder sees neither the row nor its scope, and would not
write index columns. Seal values of bound and indexed seals explicitly. Explicit operations
are useful when dependencies and plaintext access should be visible at the call
site. Automatic adapters are useful when
encryption belongs consistently at the database boundary.

The application owns database schemas, transactions, query construction, and
concurrency policy. SQLx features do not choose the application's async runtime
or TLS configuration. Serde handles stored bytes only and supplies neither
encryption nor atomic persistence. See [features and platforms](features.md) for
exact availability and configuration requirements.

Try [explicit SQLite storage](../examples/sqlite/README.md), the
[automatic-adapter example](testing.md#automatic-adapters), or
[stored-value serialization](../examples/stored_values/README.md).

## Keyrings and key sources

A **keyring** holds one current key generation and the previous generations
that stored data still needs: `EncryptionKeyring` for values and
`BlindIndexKeyring` for blind indexes. `Keys` pairs an encryption keyring with an
optional blind-index keyring. The **installed keys** back the process-wide forms,
and a **`ColumnKeys`** type selects the keys of an automatic SQLx column.

Which keyring protects which seal and scope is the decision with the most
silent failure modes; [choosing keyrings](choosing-keyrings.md) covers it in
full, and [shredding a scope](shredding.md) covers what destroying one scope's
keys does.

Operations take keys directly. Explicit `Sealed::seal`, `open`, `prepare`,
`with_index_with`, and `probes_with` calls accept any **key source**
(`EncryptionKeySource` or `BlindIndexKeySource`) and never read the installed
keys. The library passes the source the seal (or index) and the binding's key
scope; keyrings and `Keys` ignore both and return themselves. This allows each
test or application component to own its dependencies.

Choosing which keyring protects which seal or scope is application code. Pass
the payments keyring when sealing an IBAN and the general keyring when sealing an
email, or implement a key source that picks one by seal or keys view. Opening
with the wrong keyring fails loudly with `Error::UnknownEncryptionKey`, as long
as key IDs are generated UUIDs, unique within a keyring, and never shared across
keyrings. Sealing with the wrong keyring succeeds silently, so test the choice:
[choosing keyrings](choosing-keyrings.md) lists the failure modes, the key-ID
rules, and how to record and test custody.

The process-wide forms (`Sealed::seal_global`, `open_global`, `with_index()`,
`probes()`) are the explicit forms called with `keys::installed()`. Like the
automatic column, `seal_global` and `open_global` serve only unscoped seals
without a record.
`keys::install(keys)` sets the installed keys once per process, from the binary
entry point; a second call returns `AlreadyInstalled` and never replaces them.
Before installation the process-wide forms return `Error::KeysNotInstalled`: there is
no default and no panic. There are no thread- or task-scoped keys, because work
spawned outside a scope would silently use other keys
([ADR-0004](adr/0004-key-supply-global-and-explicit.md)).

The automatic SQLx column `Plain<F, K>` takes its key source as a type,
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

Key sources are synchronous. Applications load secrets from their chosen
source and build keyrings locally; CryptBox does not distribute secrets or
refresh remote key-management state. Startup snapshots are simple, but changing
their source files does not refresh a running process. A custom refreshing
key source owns synchronization, availability, and consistent generation
selection, and returns `Error::KeysUnavailable` when its keys are not loaded.

For durable data, the public generation ID and root material are one immutable
pair. Reload that exact pair after restarts and retain readable generations while
stored data needs them. Replacing a missing key with a newly generated one cannot
recover existing ciphertext. Encryption and blind-index roles use independently
generated roots; encryption-only applications need no index roots.

The [SQLite example](../examples/sqlite/README.md#2-provision-the-demonstration-key-once) shows
a single durable encryption generation. The [searchable example](../examples/searchable/README.md#provision-durable-key-generations-once)
adds independent index generations. For a custom key source, see
[key source contracts](../examples/custom_field/README.md#implementor-obligations); for changing a
serving keyset, see [key lifecycle](key-rotation.md).

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
[index binding](wire-format.md#index-binding): the values of its index scope,
which holds the seal's keys view. Equal values under different keys views
therefore have different index bytes, and a query supplies the index
scope. The seal's other parts and the record do not participate unless the index
scope names them, and the record never does, because a query cannot know it, so
by default equal values in two workspaces of one org share index bytes. Choose
index scopes with that in mind; see
[bindings](bindings.md#choose-each-blind-indexs-scope).

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

Seals, value types, codecs, normalizers, bindings, and key sources are
extensible; padding policies are a closed set of built-in const policies. A
codec or normalizer cannot add scope or record authentication: that comes from
the seal's [binding](bindings.md). The
[custom-field example](../examples/custom_field/README.md)
shows a zeroizing value, codec, normalizer, and key source working together.

## From design to a working application

- [Bindings](bindings.md) covers declaring a scope, its views, record IDs, and
  where each bound value must come from.
- [Choosing keyrings](choosing-keyrings.md) covers custody, key-ID rules, and
  testing which keyring protects which seal.
- [Testing and diagnostics](testing.md) covers key isolation and sanitized failures.
- [Legacy adoption](legacy-migration.md) addresses existing plaintext or foreign
  ciphertext; review its prerequisites before enabling new encrypted writes.
- [Security](security.md) describes the trust boundary and application responsibilities.
- [Key lifecycle](key-rotation.md) and [maintenance sweeps](reencryption-sweep.md)
  cover rollout and later rewriting. Rotation and schema evolution are separate changes.
