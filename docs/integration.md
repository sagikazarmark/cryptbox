# Integration design and trade-offs

After a first round trip, the main design questions are where encryption happens,
which policy remains stable with stored data, and how keys reach each operation.
This page explains those choices and their consequences. It builds on
[how CryptBox works](concepts.md); for a runnable next step, follow the
[durable SQLite example](../examples/sqlite/README.md).

## Persistent schema

Encrypted storage is not entirely self-describing. An envelope identifies its
format, suite, and encryption-key generation, but the application supplies the
expected field ID, codec, and padding policy. A blind index additionally depends
on a logical index ID and normalization rule that are not stored with it.

These choices form persistent schema just as database column types do:

| Choice | Why it must remain compatible |
| --- | --- |
| Value type and codec | Authenticated bytes still need to decode into the intended application value. A different codec can decode existing bytes into a wrong value without an error. |
| Field ID | Every value is bound to its field ID; a different ID fails authentication. |
| Padding enabled/disabled | The envelope does not say whether the decrypted bytes contain padding. |
| Index ID and normalization | Writers, queries, and candidate comparisons must agree on the meaning of equality. |
| Index precision | Stored indexes and probes must use the same retained bit count. |

Rust type names are not cryptographic identities. Renaming
a type does not change its field ID; generating a new ID does. Changing these
policies requires a compatibility and migration plan, not just a new deployment.
The [legacy migration guide](legacy-migration.md) covers adopting CryptBox over
plaintext or another encryption solution; it is not a general field-schema
migration procedure.

A value type's `Plaintext` implementation names its default codec: `Utf8` for
`String` and `Secret<String>`, `Raw` for `Vec<u8>` and `Secret<Vec<u8>>`. These
mappings are permanent and no feature changes them. Other value types, including
Serde types, either name their codec on the field or implement `Plaintext`
themselves; that mapping is persistent schema too. Two fields over one value type
(`HomeAddress` and `BillingAddress` over `Address`) have separate field IDs, so
their ciphertext cannot be swapped.

Padding has one useful exception: removal depends on the padding marker, not the
original block size or target length. Changing parameters of an already-padded
field preserves readability, while enabling or disabling padding requires
migration. Current padding parameters also do not impose a limit on historical
reads. See the [size and padding contracts](wire-format.md#plaintext-padding).

## Storage boundaries

The choice between explicit operations and automatic adapters determines where
keys are needed and where plaintext becomes available:

| Approach | Behavior and consequence |
| --- | --- |
| Explicit encryption or preparation | Produce ciphertext before calling storage. Key failures happen at that explicit step; the stored representation can then cross a database or serialization boundary. |
| Read as `Ciphertext<F>` | SQLx decoding or Serde deserialization checks structure without keys. The application chooses when to authenticate and decrypt. Useful when only some loaded values need plaintext. |
| Automatic SQLx `Encrypted<F>` | The adapter encrypts on encode and authenticates/decrypts on decode. It reads keys from its key context: the installed keys by default, so ordinary database conversion needs `keys::install`, or an application-owned static named as `Encrypted<F, K>`. |

Automatic SQLx adapters are available for every field. Explicit-provider operations are useful when dependencies and plaintext
access should be visible at the call site. Automatic adapters are useful when
encryption belongs consistently at the database boundary.

The application owns database schemas, transactions, query construction, and
concurrency policy. SQLx features do not choose the application's async runtime
or TLS configuration. Serde handles stored bytes only and supplies neither
encryption nor atomic persistence. See [features and platforms](features.md) for
exact availability and configuration requirements.

Try [explicit SQLite storage](../examples/sqlite/README.md), the
[automatic-adapter example](testing.md#automatic-adapters), or
[stored-value serialization](../examples/stored_values/README.md).

## Key providers and key contexts

A provider is the source of current and readable key generations. The
**installed keys** back the implicit forms, and a **key context** selects the
keys of an automatic SQLx column. The field ID determines where a value belongs;
it never supplies key material, but every provider request names the field it
serves.

A provider that serves every field alike, such as the local keyrings, ignores
the field. To protect fields with different key hierarchies, route them with
`Router`: `Router::strict().route::<Iban>(payments)?.route::<UserEmail>(general)?`.
A strict router rejects unrouted fields with `Error::UnroutedField` instead of
substituting another provider's keys. `Router::new(default)` serves unrouted
fields from `default`, and `Router::falls_back` reports which fields rely on it.
A second route for the same field ID is rejected. Routes are deployment
configuration: the envelope records the key ID, so a field can move to another
provider that resolves the same generations.

Explicit `encrypt_with`, `decrypt_with`, `prepare_with`, and `probes_with` calls
use the provider passed by the caller and never read the installed keys. This
allows each test or application component to own its dependencies. `Keys`
combines an encryption and a blind-index provider, usually two routers, into one
value that every explicit form accepts.

The implicit forms (`encrypt()`, `decrypt()`, `prepare()`, `with_index()`,
`probes()`) are the explicit forms called with `keys::installed()`.
`keys::install(keys)` sets the installed keys once per process, from the binary
entry point; a second call returns `AlreadyInstalled` and never replaces them.
Before installation the implicit forms return `Error::KeysNotInstalled`: there is
no default and no panic. There are no thread- or task-scoped keys, because work
spawned outside a scope would silently use other keys
([ADR-0004](adr/0004-key-supply-global-and-explicit.md)).

The automatic SQLx column `Encrypted<F, K>` takes its key source as a type,
because SQLx decoding receives no context. The default `K`, `GlobalKeys`, reads
the installed keys. Implement `KeyContext` over an application-owned static to
use a second keyring, a tenant, or a test fixture without the global. A field
does not choose its keys: route fields to providers instead.

Teams that forbid the global can deny `keys::install` and the implicit forms with
Clippy's `disallowed_methods`, using
[this `clippy.toml`](snippets/clippy-no-global-keys.toml). Denying `install` alone
keeps the installed keys empty, so implicit calls fail at run time; denying the
implicit forms also reports them at lint time. With the `migrate` feature, also
deny `MaybeEncrypted::decrypt` and `MaybeEncrypted::decrypt_legacy`.

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

The [SQLite example](../examples/sqlite/README.md#2-provision-the-demonstration-key-once) shows
a single durable encryption generation. The [searchable example](../examples/searchable/README.md#provision-durable-key-generations-once)
adds independent index generations. For a custom key source, see
[provider contracts](../examples/custom_field/README.md#implementor-obligations); for changing a
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

The [searchable storage example](../examples/searchable/README.md) demonstrates the complete write
and lookup path together. Adding search to existing data also requires a plan to
populate and verify indexes before relying on index-only queries.

## Plaintext lifetime and extension points

Application values remain plaintext in memory. Borrowing them for encryption or
preparation does not erase them, and decoded values have their own lifetimes.
`Secret<T>` can zeroize a compatible owned value on drop; it does not erase other
copies. The [ownership reference](ownership.md) defines exact behavior by type
and buffer.

Fields, value types, codecs, normalizers, and key providers are extensible. Bindings and
padding policies are sealed to the built-in choices; a custom codec cannot add
row or tenant authentication. The [custom-field example](../examples/custom_field/README.md)
shows a zeroizing value, codec, normalizer, and provider working together.

## From design to a working application

- [Testing and diagnostics](testing.md) covers provider isolation and sanitized failures.
- [Legacy adoption](legacy-migration.md) addresses existing plaintext or foreign
  ciphertext; review its prerequisites before enabling new encrypted writes.
- [Security](security.md) describes the trust boundary and application responsibilities.
- [Key lifecycle](key-rotation.md) and [maintenance sweeps](reencryption-sweep.md)
  cover rollout and later rewriting. Rotation and schema evolution are separate changes.
