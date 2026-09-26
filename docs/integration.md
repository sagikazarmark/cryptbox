# Integration design and trade-offs

After a first round trip, the main design questions are where encryption happens,
which policy remains stable with stored data, and how keys reach each operation.
This page explains those choices and their consequences. It builds on
[how CryptBox works](concepts.md); for a runnable next step, follow the
[durable SQLite tutorial](first-field-sqlite.md).

## Persistent schema

Encrypted storage is not entirely self-describing. An envelope identifies its
format, suite, and encryption-key generation, but the application supplies the
expected binding, codec, and padding policy. A blind index additionally depends
on a logical index ID and normalization rule that are not stored with it.

These choices form persistent schema just as database column types do:

| Choice | Why it must remain compatible |
| --- | --- |
| Codec | Authenticated bytes still need to decode into the intended application value. |
| Binding and field ID | Decryption uses the expected domain; a different domain fails authentication. |
| Padding enabled/disabled | The envelope does not say whether the decrypted bytes contain padding. |
| Index ID and normalization | Writers, queries, and candidate comparisons must agree on the meaning of equality. |
| Index precision | Stored indexes and probes must use the same retained bit count. |

Rust type names and diagnostic labels are not cryptographic identities. Renaming
a type does not change its field ID; generating a new ID does. Changing these
policies requires a compatibility and migration plan, not just a new deployment.
The [legacy migration guide](legacy-migration.md) covers adopting CryptBox over
plaintext or another encryption solution; it is not a general profile-schema
migration procedure.

Padding has one useful exception: removal depends on the padding marker, not the
original block size or target length. Changing parameters of an already-padded
profile preserves readability, while enabling or disabling padding requires
migration. Current padding parameters also do not impose a limit on historical
reads. See the [size and padding contracts](wire-format.md#plaintext-padding).

## Storage boundaries

The choice between explicit operations and automatic adapters determines where
keys are needed and where plaintext becomes available:

| Approach | Behavior and consequence |
| --- | --- |
| Explicit encryption or preparation | Produce ciphertext before calling storage. Key failures happen at that explicit step; the stored representation can then cross a database or serialization boundary. |
| Read as `Ciphertext<T, Profile>` | SQLx decoding or Serde deserialization checks structure without keys. The application chooses when to authenticate and decrypt. Useful when only some loaded values need plaintext. |
| Automatic SQLx `Encrypted<T, Profile>` | The adapter encrypts on encode and authenticates/decrypts on decode. It resolves providers through the profile's key context, so ordinary database conversion needs that context available. |

Automatic SQLx adapters are available for unit-context profiles. Both current
bindings, `Unbound` and `FieldBound<F>`, use unit context; field binding still
applies. Explicit-provider operations are useful when dependencies and plaintext
access should be visible at the call site. Automatic adapters are useful when
encryption belongs consistently at the database boundary.

The application owns database schemas, transactions, query construction, and
concurrency policy. SQLx features do not choose the application's async runtime
or TLS configuration. Serde handles stored bytes only and supplies neither
encryption nor atomic persistence. See [features and platforms](features.md) for
exact availability, including unreleased Serde support.

Try [explicit SQLite storage](first-field-sqlite.md), the
[automatic-adapter example](testing.md#automatic-adapters), or
[stored-value serialization](stored-values.md).

## Key providers and key contexts

A provider is the source of current and readable key generations. A **key
context** selects the providers used by context-less operations and automatic
adapters. A **binding context** supplies runtime information for a binding; it
does not supply keys. These are separate responsibilities even though both
appear in the profile API.

Explicit `encrypt_with`, `decrypt_with`, and `prepare_with` calls use the provider
passed by the caller. This allows each test or application component to own its
dependencies. Context-less calls and automatic adapters use `Profile::Keys`.
`GlobalKeyContext` is installed once per process and cannot be reset. A custom
key context can expose application-owned providers, with their own lifetime and
synchronization policy.

Providers resolve keys synchronously. Applications load secrets from their chosen
source and make them available locally; CryptBox does not distribute secrets or
refresh remote key-management state. Startup snapshots are simple, but changing
their source files does not refresh a running process. A custom refreshing
provider owns synchronization, availability, and consistent generation selection.

For durable data, the public generation ID and root material are one immutable
pair. Reload that exact pair after restarts and retain readable generations while
stored data needs them. Replacing a missing key with a newly generated one cannot
recover existing ciphertext. Encryption and blind-index roles use independently
generated roots; encryption-only applications need no index roots.

The [SQLite tutorial](first-field-sqlite.md#2-provision-the-demonstration-key-once) shows
a single durable encryption generation. The [searchable tutorial](searchable-sqlx.md#2-provision-durable-key-generations-once)
adds independent index generations. For a custom key source, see
[provider contracts](custom-profile.md#implementor-obligations); for changing a
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
encryption of one column does not maintain another column.

Search availability also depends on retaining all readable index-key generations.
An application can decrypt a row successfully yet omit it from lookup if the
corresponding index generation is unavailable. Checking candidate plaintext and
checking stored-index consistency are separate tasks; see
[what each check establishes](security.md#what-each-check-establishes).

The [searchable SQLx tutorial](searchable-sqlx.md) demonstrates the complete write
and lookup path together. Adding search to existing data also requires a plan to
populate and verify indexes before relying on index-only queries.

## Plaintext lifetime and extension points

Application values remain plaintext in memory. Borrowing them for encryption or
preparation does not erase them, and decoded values have their own lifetimes.
`Secret<T>` can zeroize a compatible owned value on drop; it does not erase other
copies. The [ownership reference](ownership.md) defines exact behavior by type
and buffer.

Codecs, normalizers, profiles, and key providers are extensible. Bindings and
padding policies are sealed to the built-in choices; a custom codec cannot add
row or tenant authentication. The [custom-profile example](custom-profile.md)
shows a zeroizing value, codec, normalizer, and provider working together.

## From design to a working application

- [Testing and diagnostics](testing.md) covers provider isolation and sanitized failures.
- [Legacy adoption](legacy-migration.md) addresses existing plaintext or foreign
  ciphertext; review its prerequisites before enabling new encrypted writes.
- [Security](security.md) describes the trust boundary and application responsibilities.
- [Key lifecycle](key-rotation.md) and [maintenance sweeps](reencryption-sweep.md)
  cover rollout and later rewriting. Rotation and schema evolution are separate changes.
