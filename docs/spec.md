# CryptBox — v0.1 Design Specification

**Project:** CryptBox
**Primary Rust crate:** `cryptbox`
**Status:** Draft
**Scope:** Core encrypted-value abstraction, key management model, blind equality indexes, codecs, and initial SQLx integration
**Audience:** Library implementers, security reviewers, adapter authors, and application developers

## 1. Purpose

CryptBox provides strongly typed, application-layer encryption for Rust values.

Its primary abstraction is an application value that exists as plaintext while in use by the application but is encrypted when crossing supported persistent-storage boundaries.

The library is intended to support use cases such as:

```rust
use cryptbox::Encrypted;

struct User {
    id: Uuid,
    email: Encrypted<String, UserEmail>,
    phone: Encrypted<String, UserPhone>,
}
```

with storage such as:

```text
users
┌────────────┬──────────────────────┬──────────────────────┐
│ id         │ email                │ phone                │
│ UUID       │ encrypted bytes      │ encrypted bytes      │
└────────────┴──────────────────────┴──────────────────────┘
```

The initial storage integration is SQLx. The CryptBox core MUST NOT depend on SQLx or on any specific database.

The architecture MUST permit future integrations with Diesel, Serde-based storage, Redis, files, message queues, or other byte-oriented storage systems without changing the cryptographic core.

---

# 2. Project and crate naming

The project name is **CryptBox**.

The primary crate SHOULD be published as:

```text
cryptbox
```

If integrations eventually warrant separate crates, they SHOULD follow a predictable naming convention:

```text
cryptbox
cryptbox-sqlx
cryptbox-diesel
cryptbox-serde
cryptbox-derive
```

However, v0.1 SHOULD prefer Cargo features inside a single `cryptbox` crate unless a technical reason requires separation.

Example:

```toml
cryptbox = {
    version = "0.1",
    features = ["sqlx-postgres", "json", "postcard"]
}
```

The project name MUST NOT leak into fundamental cryptographic terminology merely for branding purposes.

Public concepts SHOULD use conventional names such as:

```rust
Encrypted<T, Profile>
Secret<T>
Ciphertext<T, Profile>
BlindIndex
KeyId
Keyring
```

rather than branded equivalents.

**Rationale:** The package can have a memorable identity while the API remains boring, precise, and recognizable to Rust developers.

---

# 3. Design principles

The following principles are foundational.

## 3.1 The crypto core operates on bytes

The cryptographic layer MUST NOT know about:

- Rust domain types;
- Serde;
- SQL;
- SQLx;
- table names;
- database column names;
- ORM models.

Its conceptual interface is:

```text
plaintext bytes
      +
binding context
      +
key provider
      ↓
encryption suite
      ↓
ciphertext envelope
```

Decryption reverses this process.

Typed serialization and storage integration exist above this layer.

**Rationale:** This keeps cryptographic behavior independently reviewable and prevents framework-specific requirements from shaping the encryption protocol. Fieldseal adopts a similar separation between its cryptographic core and ORM adapters.

---

## 3.2 Typed values are an application-layer abstraction

The main public type SHOULD be:

```rust
Encrypted<T, Profile>
```

rather than exposing every policy decision as an independent generic parameter.

A profile describes the policy for a particular logical encrypted value:

```rust
trait EncryptionProfile<T> {
    type Codec: Codec<T>;
    type Binding: Binding;
    type Keys: KeyContext;
}
```

A typical declaration may look like:

```rust
struct UserEmail;

impl EncryptionProfile<String> for UserEmail {
    type Codec = Utf8;
    type Binding = FieldBound<USER_EMAIL_FIELD_ID>;
    type Keys = ApplicationKeys;
}

type Email = Encrypted<String, UserEmail>;
```

The exact syntax is illustrative rather than normative.

**Rationale:** A design such as:

```rust
Encrypted<T, Context, Codec, Provider, ...>
```

makes types noisy and leaks implementation details into application models. Profiles keep application types readable while preserving compile-time policy.

---

# 4. Threat model

## 4.1 In scope

CryptBox is intended to protect plaintext against an adversary who obtains:

- a database dump;
- database read access;
- backups;
- snapshots;
- detached database volumes;
- ciphertext stored by another supported adapter.

CryptBox also provides authenticated encryption, so unauthorized modification of ciphertext MUST be detectable.

When field binding is enabled, CryptBox additionally protects against moving ciphertext from one logical encrypted field into another.

Blind indexes intentionally weaken confidentiality and are addressed separately.

---

## 4.2 Out of scope

CryptBox does NOT protect plaintext if an attacker compromises the application process while the application possesses usable key material.

It does not claim to protect against:

- arbitrary application-process compromise;
- runtime memory inspection while secrets are live;
- malicious application code;
- query-pattern analysis;
- access-pattern analysis;
- plaintext written to application logs;
- plaintext deliberately exposed through application APIs;
- side channels outside the library's control.

Database query logs, application logs, tracing systems, crash dumps, swap, and similar artifacts SHOULD be treated as sensitive.

---

# 5. Core value types

The conceptual model consists of three different kinds of value.

## 5.1 `Encrypted<T, Profile>`

```rust
Encrypted<T, Profile>
```

represents an application value whose persistent representation is required to be encrypted.

Despite its name, an `Encrypted<T, Profile>` MAY contain plaintext `T` while present in application memory.

The documentation MUST state this clearly.

`Encrypted<T, Profile>` MUST NOT implement `Display`.

Its `Debug` representation MUST redact plaintext, for example:

```text
Encrypted([REDACTED])
```

It MUST NOT implement:

```rust
Deref<Target = T>
```

Plaintext access SHOULD require an explicit method such as:

```rust
value.expose_secret()
```

**Rationale:** Accidental logging is a realistic source of secret leakage. Making exposure explicit follows the successful design philosophy of secret-container libraries such as `secrecy`.

---

## 5.2 `Secret<T>`

`Secret<T>` represents plaintext with stronger memory-handling semantics.

It SHOULD require:

```rust
T: Zeroize
```

and MUST zeroize its contents on drop.

It SHOULD have the same explicit-exposure and redacted-debug semantics as `Encrypted<T, Profile>`.

`Secret<T>` is OPTIONAL for applications using `Encrypted<T, Profile>`.

Arbitrary encrypted domain types MUST NOT be required to implement `Zeroize`.

**Rationale:** Requiring every `T` to implement `Zeroize` would prevent encryption of many useful domain and third-party types. CryptBox can guarantee zeroization only for memory it controls.

---

## 5.3 `Ciphertext<T, Profile>`

`Ciphertext<T, Profile>` represents an encrypted binary envelope whose expected plaintext type and policy are represented by phantom type information.

It MUST NOT imply that the ciphertext has successfully authenticated until decryption succeeds.

This type is useful for:

- explicit cryptographic APIs;
- migration tooling;
- future context-aware row adapters;
- transporting encrypted representations without decrypting them.

---

# 6. Zeroization

CryptBox MUST zeroize:

- root encryption key material;
- derived encryption keys;
- blind-index key material;
- temporary plaintext byte buffers created during encoding;
- temporary plaintext byte buffers created during decryption.

The `zeroize` crate or an equivalently strong mechanism SHOULD be used.

CryptBox MUST NOT claim that arbitrary `T` is zeroized merely because its temporary serialized representation is zeroized.

For example:

```text
MyStruct in memory
        ↓
serialize
        ↓
temporary plaintext Vec<u8>
        ↓
encrypt
        ↓
zeroize temporary Vec<u8>
```

does not erase the original `MyStruct`.

Applications requiring stronger in-memory guarantees SHOULD use `Secret<T>` where `T: Zeroize`.

---

# 7. Value codecs

Serialization of `T` and encryption are independent operations.

CryptBox MUST define an abstraction conceptually equivalent to:

```rust
trait Codec<T> {
    fn encode(value: &T) -> Result<Zeroizing<Vec<u8>>, CodecError>;
    fn decode(bytes: &[u8]) -> Result<T, CodecError>;
}
```

Built-in codecs SHOULD initially include:

```text
Raw
Utf8
Json
Postcard
```

Additional codecs MAY be added later.

## 7.1 Serialization support is determined at compile time

There MUST NOT be runtime detection such as:

```text
if T is String:
    use UTF-8
else if T implements Serialize:
    use JSON
```

Instead, codec implementations use ordinary Rust trait bounds.

For example:

```rust
impl<T> Codec<T> for Json
where
    T: Serialize + DeserializeOwned,
{
    ...
}
```

`DeserializeOwned` SHOULD be required for Serde-based decoding because decrypted temporary byte buffers are destroyed after decoding and the resulting `T` must not borrow from them.

---

## 7.2 Codec choice is not encoded in ciphertext

The ciphertext envelope MUST NOT contain a JSON/Postcard/UTF-8/etc. identifier.

The crypto layer encrypts opaque plaintext bytes.

Codec selection belongs to the Rust profile and application schema.

**Rationale:** Codec migration is an application-schema concern rather than a cryptographic concern. Embedding codec knowledge would unnecessarily couple CryptBox's wire format to Rust serialization choices.

---

# 8. Serde integration

## 8.1 Serde as a codec

Serde-backed codecs such as JSON or Postcard ARE in scope for v0.1.

---

## 8.2 Serializing `Encrypted<T>` itself

A blanket implementation of:

```rust
Serialize for Encrypted<T, Profile>
```

MUST NOT be provided in v0.1.

Likewise, blanket `Deserialize` support MUST NOT make it ambiguous whether an external representation contains plaintext or ciphertext.

**Rationale:** Consider:

```rust
serde_json::to_string(&user)
```

There is no universally correct answer to whether an encrypted field should become plaintext, encrypted bytes, or an encoded envelope.

An implicit choice could cause accidental disclosure.

A future explicit adapter MAY support constructs such as:

```rust
#[serde(with = "cryptbox::serde::ciphertext")]
```

or serialization of:

```rust
Ciphertext<T, Profile>
```

This is deliberately deferred.

---

# 9. Binding

Encryption MAY bind ciphertext to its logical purpose.

v0.1 defines exactly two binding modes.

## 9.1 Unbound encryption

Unbound encryption provides:

- confidentiality;
- ciphertext integrity;
- key rotation.

It does NOT protect against moving valid ciphertext between logical fields using the same encryption domain.

Unbound mode MUST be explicit in type/profile configuration.

It MUST NOT occur merely because a `FieldId` was accidentally omitted.

---

## 9.2 Field-bound encryption

Field-bound encryption additionally binds ciphertext to a stable:

```rust
FieldId
```

The `FieldId` MUST participate in cryptographic domain separation and/or authenticated context such that moving ciphertext to a different `FieldId` causes decryption to fail.

A field identifier SHOULD be a stable 128-bit random identifier, commonly represented in source code as a UUID literal.

Example:

```rust
const USER_EMAIL: FieldId =
    field_id!("ca274e85-63c4-4f7d-...");
```

A `FieldId`:

- is not secret;
- MUST remain stable for the lifetime of encrypted data;
- MUST NOT be derived directly from current SQL table/column names;
- SHOULD survive database and Rust symbol renames.

**Rationale:** Tying encryption context to `"users.email"` makes harmless schema renames cryptographic migrations.

---

## 9.3 Security properties of binding

The expected hierarchy is:

```text
Unbound
  confidentiality
  integrity

Field-bound
  confidentiality
  integrity
  cross-field substitution protection

Future tenant-bound
  +
  cross-tenant substitution protection

Future record-bound
  +
  cross-row substitution protection
```

A `FieldId` does NOT prevent moving Alice's encrypted email into Bob's `email` field because both values use the same logical field identity.

Preventing that requires runtime record context and is intentionally deferred.

---

# 10. Future runtime binding model

Although v0.1 implements only static bindings, the type architecture MUST leave room for bindings requiring runtime context.

A binding abstraction SHOULD be capable of expressing something conceptually like:

```rust
trait Binding {
    type Context;
}
```

For v0.1:

```text
Unbound.Context    = ()
FieldBound.Context = ()
```

Future versions may define:

```text
TenantBound.Context       = TenantContext
RecordBound.Context       = RecordContext
TenantRecordBound.Context = TenantRecordContext
```

No public tenant or record context representation SHALL be standardized in v0.1.

**Rationale:** Defining `Option<tenant_id>` now would prematurely freeze canonical tenant-ID encoding, key-scoping semantics, SQLx behavior, and context composition before CryptBox has an implementation that needs them.

---

# 11. Key architecture

Cryptographic operations and key retrieval are separate responsibilities.

The design distinguishes:

```text
EncryptionSuite
EncryptionKeyProvider
BlindIndexKeyProvider
KeyContext
```

A single "crypto provider" combining all of these SHOULD NOT be the foundational abstraction.

---

# 12. Runtime key injection

Keys MAY originate from:

- environment variables;
- command-line arguments;
- secret files;
- process supervisors;
- secret stores;
- test configuration;
- future KMS-backed providers.

CryptBox MUST NOT dictate configuration transport.

For context-less adapters such as SQLx scalar `Encode`/`Decode`, runtime-created providers MAY be installed into process-global initialized-once state.

Conceptually:

```rust
static KEYS: OnceLock<KeyProvider> = OnceLock::new();
```

Application startup can therefore do:

```rust
let keys = load_keys_from_environment()?;
ApplicationKeys::install(keys)?;
```

and later obtain:

```rust
&'static KeyProvider
```

from SQLx integration code.

"Static" in this context means statically reachable after initialization, NOT compiled into the program.

The explicit core encryption API MUST also permit direct provider injection and MUST NOT require global state.

---

# 13. Encryption key rotation

Key rotation is a first-class v0.1 feature.

An encryption keyring MUST contain:

```text
exactly one current key
zero or more historical keys
```

The current key is used for:

```text
encrypt + decrypt
```

Historical keys are used for:

```text
decrypt only
```

Conceptually:

```rust
struct EncryptionKeyring {
    current: CurrentKey,
    previous: HashMap<KeyId, PreviousKey>,
}
```

---

## 13.1 Key identifiers

Every encryption key MUST have an opaque non-secret `KeyId`.

A 128-bit random identifier is RECOMMENDED.

A key identifier MUST NOT be derived directly from key bytes.

---

## 13.2 Encryption behavior

All new encryption MUST use the current key.

---

## 13.3 Decryption behavior

The ciphertext envelope identifies its `KeyId`.

Decryption MUST:

1. parse the envelope;
2. obtain its `KeyId`;
3. ask the provider for that exact key;
4. decrypt using that key.

Implementations MUST NOT trial-decrypt against every historical key.

A missing historical key MUST result in an explicit error such as:

```rust
UnknownEncryptionKey(KeyId)
```

---

## 13.4 Rotation does not require immediate data migration

Changing:

```text
current = K2
```

to:

```text
current  = K3
previous = [K2, K1]
```

is itself considered key rotation.

Existing K1/K2 ciphertext remains readable.

New writes use K3.

This operation MUST NOT require a synchronous database rewrite.

---

## 13.5 Re-encryption is separate

Rewriting existing ciphertext to the current key is called **re-encryption**, not rotation.

The core SHOULD expose operations equivalent to:

```rust
needs_reencryption(ciphertext)
reencrypt(ciphertext, context, provider)
```

`needs_reencryption` SHOULD normally be answerable from envelope metadata without decrypting the payload.

---

## 13.6 No automatic re-encryption on reads

SQLx `Decode` MUST NOT silently update old ciphertext.

A read MUST remain a read.

**Rationale:** Read-triggered mutation interferes with read replicas, read-only transactions, auditing, locking, and predictable application behavior.

Values naturally converge when an application later writes them because writes always use the current key.

A full maintenance sweep remains optional.

---

# 14. Key derivation and field separation

Keys returned by the application-level encryption key provider SHOULD be treated as root encryption keys rather than used directly for every field.

The selected encryption suite SHOULD derive operational encryption keys using the binding domain.

Conceptually:

```text
root key
   │
   ├── Unbound domain
   │       ↓
   │   encryption key
   │
   └── FieldId A
           ↓
       field encryption key
```

The exact KDF is part of the cipher-suite definition.

**Rationale:** Per-field domain separation limits accidental key reuse and follows the same general principle used by CipherSweet.

---

# 15. Ciphertext envelope

CryptBox SHALL use its own versioned binary ciphertext envelope rather than requiring CipherSweet compatibility.

The envelope conceptually contains:

```text
magic
format_version
suite_id
key_id
suite_payload
```

where `suite_payload` contains suite-specific information such as:

```text
nonce
ciphertext
authentication tag
```

The exact binary layout SHALL be frozen before a production release and covered by test vectors.

---

## 15.1 Authentication

All security-relevant envelope metadata, including at least:

```text
format_version
suite_id
key_id
binding/domain information
```

MUST be cryptographically authenticated either directly as AAD or through an equivalent reviewed construction.

Modifying a `key_id`, suite identifier, or binding context MUST NOT permit successful decryption.

---

## 15.2 Suite identification

Ciphertexts MUST identify the cipher suite required to decrypt them.

This allows algorithm migrations to coexist with key migrations.

New encryption uses the configured active suite.

A maintenance re-encryption operation MAY migrate both suite and key simultaneously.

---

## 15.3 Why not CipherSweet wire compatibility?

CipherSweet is a major design reference and deliberately documents its internals to enable compatible cross-language implementations.

However, CryptBox's chosen key-rotation model requires every ciphertext to identify its key generation directly.

CryptBox therefore uses a native envelope optimized around:

```text
current key + historical decrypt-only keys
```

CipherSweet compatibility MAY later be implemented as an alternate encryption format.

---

## 15.4 Why not implement Fieldseal v0.1?

Fieldseal contains several strong architectural ideas that influence CryptBox, including explicit context binding, self-describing envelopes, key versions, separate blind-index keys, and clean separation between core crypto and adapters.

However, its current specification is an early working draft and is not yet an appropriate protocol to freeze CryptBox around.

Fieldseal compatibility MAY be reconsidered when its specification becomes stable and reviewed.

---

# 16. Cipher suite selection

The envelope supports a suite registry, but the exact first cryptographic suite is intentionally NOT finalized by this design specification.

The first production suite MUST:

- provide authenticated encryption;
- use a well-reviewed construction;
- provide at least 128-bit authentication strength;
- have a clear nonce-generation policy;
- support safe domain separation/key derivation;
- be backed by a mature Rust implementation;
- receive focused cryptographic review before the envelope is frozen.

Applications MUST NOT be allowed to freely compose arbitrary primitives such as:

```text
cipher + MAC + KDF + nonce strategy
```

at runtime.

Instead, each `suite_id` identifies a complete reviewed construction.

### Deferred decision

Selection of the first concrete suite is a **pre-release security-review task**, not an application-API question.

This is intentionally delayed because inventing or casually selecting a cryptographic composition is higher risk than designing the Rust type/storage abstraction.

---

# 17. Blind indexes

Blind indexes provide limited searchability over randomized encrypted values.

They are explicitly optional.

A blind index MUST be stored separately from ciphertext.

For example:

```sql
CREATE TABLE users (
    id          UUID PRIMARY KEY,
    email       BYTEA NOT NULL,
    email_bidx  BYTEA NOT NULL
);

CREATE INDEX users_email_bidx_idx
    ON users(email_bidx);
```

---

# 18. Blind-index specification

A blind index is defined by a strongly typed specification conceptually similar to:

```rust
trait BlindIndexSpec<Input> {
    const ID: IndexId;

    fn normalize(input: &Input) -> Result<Zeroizing<Vec<u8>>, Error>;

    const BITS: usize;
}
```

`Input` is intentionally generic rather than necessarily equal to the encrypted value's `T`.

This permits future compound indexes.

---

## 18.1 Stable `IndexId`

Every logical blind index MUST have a stable `IndexId`.

It SHOULD be a random 128-bit identifier.

It MUST survive Rust symbol and database-column renames.

Changing index semantics SHOULD normally result in a new `IndexId`.

---

## 18.2 Normalization

Blind-index normalization MUST be deterministic.

Examples may include:

- case normalization;
- Unicode normalization;
- extracting a domain;
- application-specific canonicalization.

CryptBox SHOULD avoid opinionated domain-specific normalization rules where semantics are ambiguous.

Once persisted data exists for a particular index definition, changing its normalization rules constitutes an index migration.

---

## 18.3 Blind indexes use separate keys

Blind indexes MUST NOT use encryption keys.

There SHALL be a distinct:

```rust
BlindIndexKeyProvider
```

or equivalent key hierarchy.

Conceptually:

```text
Encryption keyring

E3 current
E2 historical
E1 historical


Blind-index keyring

I2 current
I1 historical
```

**Rationale:** Encryption-key rotation should not force every searchable projection to be rebuilt.

---

# 19. Blind-index construction

v0.1 blind indexes support equality-style candidate lookup only.

The initial derivation SHOULD use a simple reviewed keyed construction such as a keyed hash/HMAC followed by explicit truncation.

The exact algorithm SHALL be fixed together with the v0.1 cryptographic suite review.

The index input MUST include domain separation derived from at least:

```text
binding
IndexId
normalized plaintext
```

Index keys for different indexes MUST be cryptographically separated.

---

## 19.1 Truncation

Blind indexes SHOULD support intentional truncation.

A blind index is NOT intended to function as a collision-free deterministic hash.

Unnecessarily precise blind indexes expose more equality information than necessary.

---

## 19.2 Candidate semantics

A blind-index match MUST be treated as a candidate match.

Applications MUST decrypt candidates and compare plaintext values before treating the query result as correct.

Conceptually:

```text
search plaintext
       ↓
blind index
       ↓
SQL lookup
       ↓
candidate rows
       ↓
decrypt
       ↓
plaintext verification
```

This requirement applies even if collisions are rare.

---

## 19.3 Unsupported query classes in v0.1

Blind indexes in v0.1 MUST NOT claim support for:

- ranges;
- ordering;
- arbitrary `LIKE`;
- substring search;
- full-text search;
- arbitrary prefix queries.

Only equality and `IN`-style candidate lookup are in scope.

---

## 19.4 Uniqueness

A truncated blind index MUST NOT be treated as a normal uniqueness constraint because collisions are intentional.

Application-level uniqueness over encrypted data requires additional design and is NOT solved by v0.1.

---

## 19.5 Low-cardinality values

Documentation MUST warn strongly against blind indexing low-cardinality or highly skewed sensitive values.

Examples include:

```text
boolean
small enums
binary medical outcomes
small risk categories
small geographical categories
```

Truncation does not eliminate the fundamental leakage of searchable encryption.

---

# 20. Blind-index key rotation

Blind-index key rotation SHOULD be supported in v0.1.

Like encryption keys, an index keyring has:

```text
one current key
zero or more historical keys
```

New index values use the current key.

Existing historical index values remain queryable during migration.

---

## 20.1 Stored representation

A stored blind-index value SHOULD identify the `IndexKeyId` generation used to create it.

The binary representation SHOULD conceptually contain:

```text
index_format_version
index_key_id
truncated_index
```

The exact layout SHALL be frozen with test vectors.

---

## 20.2 Query during index-key migration

If:

```text
I2 = current
I1 = historical
```

a search operation generates candidate probes using all currently readable index generations:

```text
probe(I2, search)
probe(I1, search)
```

and SQL may perform:

```sql
WHERE email_bidx IN ($1, $2)
```

New writes use only I2.

A maintenance sweep eventually rewrites historical I1 values to I2.

Once no historical values remain, I1 can be removed.

Index-key rotation is independent from encryption-key rotation.

---

# 21. Compound indexes

The v0.1 API MUST NOT assume:

```text
one encrypted value = one index input
```

`BlindIndexSpec<Input>` is deliberately generic over `Input`.

This allows a future index over:

```rust
struct NameAndPostalCode<'a> {
    name: &'a str,
    postal_code: &'a str,
}
```

or:

```rust
(&str, &str)
```

Actual compound-index convenience APIs and SQL adapters are deferred beyond v0.1.

**Rationale:** Designing the trait generically now is cheap; retrofitting compound input later could otherwise require a breaking redesign.

---

# 22. Slow blind indexes and planning

v0.1 SHOULD initially implement only one simple, reviewed fast blind-index derivation strategy.

Password-hardening/slow index strategies such as Argon2id-backed indexes are deferred.

A future version SHOULD consider:

```text
Fast
Slow
```

index strategies and an index leakage/planning tool.

### Reason for deferral

Slow index design introduces:

- parameter selection;
- memory/CPU trade-offs;
- denial-of-service considerations;
- additional algorithm policy;
- questionable benefit against online chosen-plaintext oracles.

It is not required to validate the core CryptBox design.

---

# 23. Prepared storage values

A core abstraction SHOULD exist for preparing a plaintext value for persistent storage.

Conceptually:

```rust
let prepared = value.prepare(...)?;
```

producing:

```text
Prepared
├── ciphertext
└── zero or more blind-index values
```

This operation allows ciphertext and searchable projections to be derived from exactly the same source value.

---

## 23.1 Why `Prepared` exists

SQLx represents one bound Rust value as one SQL parameter.

A custom SQLx `Encode` implementation cannot transform:

```rust
email
```

into both:

```text
email ciphertext
email blind-index column
```

automatically.

Blind-index storage therefore necessarily involves multiple SQL parameters.

`Prepared` makes this dual-write explicit and reduces synchronization errors.

---

# 24. SQLx integration

SQLx is CryptBox's first persistence adapter.

The SQLx adapter MUST remain separate from the cryptographic core.

---

## 24.1 Transparent scalar encrypted values

For profiles requiring no runtime context, SQLx SHOULD support:

```rust
Type<DB>
Encode<DB>
Decode<DB>
```

for:

```rust
Encrypted<T, Profile>
```

or appropriate closely related types.

On encode:

```text
T
↓ Codec
plaintext bytes
↓ current encryption key
ciphertext envelope
↓
database binary value
```

On decode:

```text
database binary value
↓
envelope
↓ key_id
key provider
↓
plaintext bytes
↓ Codec
T
↓
Encrypted<T, Profile>
```

---

## 24.2 Binary database representation

Encrypted values SHOULD map to native binary/blob database types, e.g.:

```text
PostgreSQL BYTEA
SQLite BLOB
MySQL BLOB/VARBINARY
```

rather than base64 text.

Text representation is an adapter concern where binary storage is unavailable.

---

## 24.3 Indexed writes

SQLx cannot transparently keep ciphertext and a second blind-index column synchronized.

Indexed inserts/updates SHOULD therefore use `Prepared`.

Example:

```rust
let prepared = email.prepare::<EmailExact>()?;

sqlx::query!(
    r#"
    UPDATE users
    SET email = $1,
        email_bidx = $2
    WHERE id = $3
    "#,
    prepared.ciphertext() as _,
    prepared.index::<EmailExact>() as _,
    id,
)
.execute(&pool)
.await?;
```

The exact API may differ, but the semantic requirement is fixed.

---

## 24.4 Indexed reads

Blind-index columns do not need to become part of ordinary domain models.

A domain model may remain:

```rust
struct User {
    id: Uuid,
    email: Encrypted<String, UserEmail>,
}
```

while queries use `email_bidx` only as a search projection.

---

## 24.5 Blind-index query verification

The SQLx adapter MUST NOT represent a blind-index query as a guaranteed exact query.

Documentation and helper APIs SHOULD encourage:

```text
generate probe
↓
query candidate rows
↓
decrypt
↓
verify normalized plaintext
```

---

# 25. Initial SQLx backend scope

PostgreSQL SHOULD be the first officially supported SQLx backend for v0.1.

SQLite and MySQL support are intentionally deferred unless their implementations prove trivial and do not delay stabilization of the core API.

### Reason for deferral

Every backend increases:

- compile-time feature complexity;
- type mapping tests;
- CI matrix size;
- macro compatibility testing;
- migration/storage edge cases.

The CryptBox core is database-independent, so additional SQLx backends can be added later without changing the cryptographic design.

---

# 26. SQLx context limitation

Scalar SQLx `Decode` cannot see sibling fields in the same row.

Therefore v0.1 SQLx scalar support is limited to bindings whose required runtime context is:

```rust
()
```

This includes:

```text
Unbound
FieldBound
```

It does NOT include future:

```text
TenantBound
RecordBound
TenantRecordBound
```

CryptBox MUST NOT introduce hidden thread-local tenant state merely to preserve transparent scalar decoding.

---

# 27. Tenancy

Tenancy is explicitly anticipated but NOT implemented in v0.1.

The future architecture should be capable of supporting two distinct properties.

## 27.1 Context binding

```text
ciphertext is authenticated against Tenant A
```

preventing cross-tenant ciphertext substitution.

## 27.2 Key isolation

```text
Tenant A key material
≠
Tenant B key material
```

limiting the blast radius if one tenant's key material is compromised.

These are different security properties and MUST NOT be conflated.

---

## 27.3 Future blind indexes and tenancy

Future tenant-aware blind indexes SHOULD avoid producing the same stored index for identical plaintext in different tenants.

For example:

```text
Tenant A + mark@example.com → A3C1...
Tenant B + mark@example.com → 91F8...
```

This may be accomplished through tenant-specific index keys or tenant context in domain-separated derivation.

---

## 27.4 Why tenancy is delayed

Implementing tenancy correctly immediately requires decisions about:

- canonical tenant-ID encoding;
- runtime cryptographic context;
- tenant-specific key lookup;
- KMS/cache behavior;
- SQLx row-aware decoding;
- tenant-aware blind-index derivation;
- record context composition;
- error behavior when context is unavailable.

Those decisions are substantial and are not required to prove the v0.1 design.

CryptBox v0.1 therefore designs the `Binding` abstraction so runtime context can be added later but exposes no tenant-specific public API.

---

# 28. Record binding

Record/row binding is also deferred.

A future record-bound mode could prevent:

```text
Alice.email ciphertext
```

from being copied into:

```text
Bob.email
```

even though both values share the same `FieldId`.

This requires a stable runtime record identifier during both encryption and decryption and therefore cannot be implemented transparently by SQLx scalar `Decode`.

It will likely require a future row-aware adapter.

---

# 29. Higher-level row adapters

A future adapter MAY support constructs conceptually similar to:

```rust
#[derive(EncryptedRow)]
struct User {
    #[tenant]
    tenant_id: Uuid,

    #[record_id]
    id: Uuid,

    #[encrypted(profile = UserEmail)]
    email: String,
}
```

which could perform context-aware conversion between:

```text
database row
↕
domain model
```

This functionality is intentionally deferred.

### Reason for deferral

Proc-macro and row-mapping ergonomics should be designed from experience using CryptBox's explicit core API rather than shaping the core around speculative ORM magic.

---

# 30. Migration behavior

The steady-state SQLx adapter MUST be strict.

If an encrypted field contains plaintext or an invalid envelope, decoding MUST fail.

The default adapter MUST NOT silently treat unknown bytes as plaintext.

---

## 30.1 Core migration primitives

The core SHOULD expose operations such as:

```rust
is_ciphertext(...)
inspect_ciphertext(...)
needs_reencryption(...)
reencrypt(...)
```

These enable applications and maintenance tools to build migrations explicitly.

---

## 30.2 Plaintext-to-encrypted migration mode

A permissive mode that accepts both plaintext and ciphertext is deliberately NOT part of normal v0.1 SQLx decoding.

A future dedicated migration adapter MAY provide this capability.

**Rationale:** A global migration mode risks becoming permanent and silently weakening the encrypted-field guarantee.

---

# 31. Algorithm migration

Algorithm migration is conceptually the same maintenance operation as re-encryption.

Because ciphertext identifies its suite:

```rust
needs_reencryption()
```

SHOULD report true when either:

```text
ciphertext.key_id != current key
```

or:

```text
ciphertext.suite_id != current suite
```

where policy requires migration.

`reencrypt()` decrypts using the historical suite/key and encrypts using the active suite/current key.

---

# 32. Errors

CryptBox MUST use structured errors.

The error taxonomy SHOULD include at least:

```rust
InvalidEnvelope
NotCiphertext
UnsupportedFormatVersion
UnsupportedSuite
UnknownEncryptionKey
UnknownBlindIndexKey
AuthenticationFailed
CodecFailed
KeyProviderUnavailable
KeyProviderNotInitialized
InvalidBlindIndex
```

`ContextMismatch` MUST NOT be reported as a distinct cryptographic fact unless the implementation can actually distinguish it from authentication failure.

Error `Display` and `Debug` output MUST NOT contain:

- plaintext;
- raw secret keys;
- derived keys;
- full ciphertext payloads.

Safe metadata such as:

```text
KeyId
SuiteId
FormatVersion
FieldId
IndexId
```

MAY appear where useful.

---

# 33. Observability

CryptBox MAY expose hooks or structured events for operational conditions such as:

```text
historical key used
unknown key encountered
reencryption needed
reencryption performed
historical index generation used
invalid envelope encountered
```

These events MUST contain metadata only and MUST NOT expose plaintext or key material.

The core SHOULD NOT require a particular logging or metrics framework.

---

# 34. Key-management network access

v0.1 key-provider operations used by encryption/decryption MUST be synchronous and local.

SQLx `Encode`/`Decode` MUST NOT perform network I/O.

A future KMS-backed provider should use a design such as:

```text
          asynchronous control path

KMS / Vault / HSM
        ↓
      warm()
        ↓
local protected/cacheable key material

-------------------------------------

          synchronous value path

encrypt
decrypt
blind index
```

This keeps network access outside framework-level scalar conversions.

---

# 35. KMS/HSM support

Direct AWS KMS, GCP KMS, Azure Key Vault, Vault Transit, or HSM integration is NOT part of v0.1.

The provider abstraction MUST nevertheless avoid assumptions that would make such providers impossible.

### Reason for deferral

KMS integration introduces:

- async APIs;
- caching;
- expiration;
- availability behavior;
- key wrapping;
- retries;
- rate limits;
- startup warming;
- failure semantics.

These are operational concerns separate from proving the core CryptBox encrypted-type model.

---

# 36. Environment variables and secret configuration

CryptBox v0.1 MAY include convenience helpers for constructing a local keyring from bytes.

It SHOULD NOT itself own environment-variable parsing policy.

Applications may do:

```rust
let encoded = Zeroizing::new(env::var("MASTER_KEY")?);
let key = decode_key(&encoded)?;

ApplicationKeys::install(
    LocalEncryptionKeyring::new(...)
)?;
```

Temporary key representations SHOULD be zeroized where possible.

Documentation SHOULD note that zeroizing the application's copy cannot retroactively erase copies maintained by the operating system or process environment.

---

# 37. Cryptographic agility

Applications MUST NOT select arbitrary low-level primitives.

Instead, a suite identifier corresponds to a complete frozen construction.

CryptBox SHOULD maintain an allow-list of suites available for encryption.

Deprecated suites MAY remain enabled for decryption during migration.

Conceptually:

```text
Suite 1
    decrypt: yes
    encrypt: no

Suite 2
    decrypt: yes
    encrypt: yes
```

This separates compatibility from current security policy.

---

# 38. Test vectors and compatibility

Before declaring the v0.1 envelope stable, CryptBox MUST publish deterministic test vectors covering at least:

- envelope parsing;
- encryption/decryption with fixed test randomness;
- every supported suite;
- bound and unbound contexts;
- wrong-field authentication failure;
- each supported key generation;
- unknown key IDs;
- re-encryption from historical to current keys;
- blind-index derivation;
- non-byte-aligned blind-index truncation if supported;
- historical index-key generations;
- codec round trips.

Once a ciphertext format is published as stable, compatibility tests MUST prevent accidental format changes.

---

# 39. Prior art and relationship to CipherSweet

CipherSweet is a major CryptBox design reference.

Relevant ideas adopted or adapted include:

- randomized field-level encryption;
- rigid cryptographic backends;
- key-domain separation;
- distinct keys for individual fields and indexes;
- blind-index truncation;
- mandatory awareness of search leakage;
- explicit key/backend migration tools.

CryptBox differs intentionally in several ways:

- Rust-native typed `Encrypted<T, Profile>`;
- codec abstraction separate from encryption;
- explicit key IDs in every native ciphertext;
- current + historical decrypt-only keyrings;
- independent root lifecycle for blind-index keys;
- explicit unbound vs field-bound modes;
- storage-framework-independent core;
- SQLx integration as an adapter rather than the primary abstraction.

CipherSweet compatibility remains a possible future encryption-format adapter.

---

# 40. Prior art and relationship to Fieldseal

Fieldseal is also a significant CryptBox design influence.

Ideas worth retaining include:

- versioned/self-describing ciphertext envelopes;
- explicit key generations;
- strong context binding;
- stable context identifiers rather than mutable SQL names;
- separate data and blind-index key roles;
- multi-version decryption;
- explicit re-encryption;
- synchronous core cryptographic operations;
- clean adapter separation;
- mandatory candidate verification after blind-index search.

CryptBox intentionally does NOT copy Fieldseal v0.1's complete protocol because the current specification is still evolving.

The CryptBox abstraction SHOULD remain capable of supporting Fieldseal as a future encryption format or compatibility layer if the protocol stabilizes.

---

# 41. v0.1 scope

CryptBox v0.1 SHOULD include:

```text
Core types
  Encrypted<T, Profile>
  Secret<T>
  Ciphertext<T, Profile>

Profiles
  Codec
  Binding
  KeyContext

Bindings
  Unbound
  FieldBound

Identifiers
  FieldId
  KeyId
  IndexId
  IndexKeyId
  SuiteId

Codecs
  Raw
  Utf8
  Serde JSON
  Postcard

Keys
  Local encryption keyring
  current + historical encryption keys
  separate blind-index keyring
  current + historical blind-index keys
  runtime initialization

Crypto
  versioned native envelope
  suite registry
  explicit provider API
  inspect / decrypt / encrypt / reencrypt

Blind indexes
  equality candidate indexes
  deterministic user-defined normalization
  explicit truncation
  stable IndexId
  query probes
  plaintext re-verification
  index-key rotation

Storage preparation
  Prepared representation

SQLx
  PostgreSQL binary storage
  scalar encrypted Encode/Decode
  typed blind-index values
  Prepared indexed writes

Security hygiene
  zeroized keys/temp buffers
  redacted Debug
  no Display/Deref
  structured errors
  test vectors
```

---

# 42. Explicitly deferred beyond v0.1

The following are deliberately outside the initial release.

## 42.1 Tenant-aware encryption

Deferred because it requires runtime context, scoped key resolution, canonical identifier encoding, and row-aware persistence integration.

The binding abstraction MUST permit its later addition without changing:

```rust
Encrypted<T, Profile>
```

---

## 42.2 Record-bound encryption

Deferred because SQLx scalar decoding cannot obtain row IDs and a higher-level row adapter is required.

---

## 42.3 Tenant-specific keyrings / crypto-shredding

Architecturally anticipated but deferred with the rest of tenancy.

---

## 42.4 Row/model derive macros

Deferred until explicit APIs reveal the correct ergonomics.

---

## 42.5 KMS/HSM providers

Deferred because they require asynchronous acquisition, caching, lifecycle policy, and operational error handling.

---

## 42.6 Automatic re-encryption on reads

Not merely deferred but intentionally excluded from the default model.

Reads should not cause hidden writes.

---

## 42.7 Permissive plaintext/ciphertext SQLx decoding

Deferred to an explicit migration facility rather than weakening normal encrypted-field semantics.

---

## 42.8 Compound blind-index convenience APIs

The trait architecture supports compound `Input`, but ORM/storage helpers are delayed.

---

## 42.9 Prefix, range, substring, and full-text encrypted search

Out of scope until there is a separately reviewed leakage model and clear use case.

---

## 42.10 Slow blind-index strategies

Deferred pending parameter design and practical experience with fast equality indexes.

---

## 42.11 Blind-index planner

Recommended for a later release but not required for proving the v0.1 abstraction.

---

## 42.12 Blanket Serde representation of `Encrypted<T>`

Intentionally omitted because plaintext-vs-ciphertext serialization semantics are context dependent.

Explicit ciphertext Serde adapters may be added later.

---

## 42.13 CipherSweet compatibility mode

Potentially valuable, but not required for CryptBox v0.1.

The native format is optimized around explicit key generations.

---

## 42.14 Fieldseal compatibility

Deferred until the Fieldseal protocol is sufficiently stable and reviewed.

---

## 42.15 SQLite and MySQL SQLx adapters

Architecturally straightforward but deferred until PostgreSQL and the core API stabilize.

---

## 42.16 First production cipher-suite choice

The suite registry and envelope support algorithm agility, but the first concrete suite must receive focused review before the wire format is frozen.

This is a deliberate security gate rather than an omitted implementation detail.

---

# 43. Security invariants

The following invariants SHOULD be treated as the most important requirements in the CryptBox specification.

**Invariant 1 — The crypto core only operates on bytes, keys, and explicit cryptographic binding.**

Framework and serialization concerns remain outside it.

**Invariant 2 — New ciphertext is always created with exactly one current encryption key.**

Historical keys are decrypt-only.

**Invariant 3 — Every ciphertext identifies the suite and key generation necessary to interpret it.**

Normal rotation never requires immediate database migration.

**Invariant 4 — Field binding, when selected, is stable and independent of database names.**

Schema renames must not silently change cryptographic identity.

**Invariant 5 — Unbound encryption is supported but explicit.**

The weaker security posture must be visible in configuration/type policy.

**Invariant 6 — Blind indexes use a key hierarchy independent from data-encryption rotation.**

Rotating encryption keys must not require rebuilding indexes.

**Invariant 7 — Blind-index hits are candidates, never authoritative matches.**

Plaintext verification is mandatory.

**Invariant 8 — Storage adapters cannot weaken the core threat model to provide framework magic.**

In particular, SQLx limitations must not distort the cryptographic API.

**Invariant 9 — Secret material and temporary plaintext owned by CryptBox are zeroized.**

CryptBox does not make false zeroization guarantees for arbitrary application values.

**Invariant 10 — Cryptographic algorithms are selected as complete reviewed suites, not user-composed primitives.**

---

# 44. Intended evolution

The expected evolution is roughly:

```text
CryptBox v0.1
│
├── typed encrypted values
├── local keyrings
├── rotation
├── codecs
├── field binding
├── equality blind indexes
└── SQLx/PostgreSQL
        │
        ▼
CryptBox v0.2+
│
├── API refinement from production usage
├── additional SQLx databases
├── compound indexes
├── migration tooling
├── derive conveniences
└── index-planning tools
        │
        ▼
later
│
├── runtime context
├── tenant binding
├── record binding
├── tenant-scoped keys
├── tenant-scoped indexes
├── row-aware SQLx adapter
├── KMS/HSM providers
├── additional storage adapters
├── explicit Serde ciphertext support
├── CipherSweet compatibility
└── possible Fieldseal compatibility
```

The central objective is that none of these future additions require replacing the fundamental:

```rust
Encrypted<T, Profile>
```

abstraction or changing the byte-oriented cryptographic core.

---

# 45. Summary

CryptBox v0.1 is intentionally ambitious about **type safety and operational correctness** but conservative about cryptographic and framework magic.

Its basic model is:

```text
arbitrary Rust value
        ↓
      Codec
        ↓
 plaintext bytes
        ↓
 optional stable field binding
        ↓
 versioned authenticated encryption
        ↓
 self-describing ciphertext
        ↓
 storage adapter
```

with independent searchable projections:

```text
plaintext
   ↓
normalization
   ↓
separately keyed blind index
   ↓
candidate lookup
   ↓
decrypt + verify
```

Key rotation is non-disruptive:

```text
K1 historical
K2 historical
K3 current

reads  → K1 / K2 / K3
writes → K3
```

and re-encryption remains an optional maintenance operation.

CryptBox v0.1 deliberately stops before tenancy, row binding, KMS integration, ORM derive magic, broad encrypted-query support, and implicit Serde behavior.

Those capabilities are anticipated structurally but postponed until the simpler core has been implemented, reviewed, and exercised in real applications.

The result should be a small, storage-independent Rust foundation for encrypted application types rather than an SQLx-specific encryption wrapper or a monolithic encrypted-database framework.
