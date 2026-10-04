# Glossary

**Blind index**:
A separately keyed, truncated searchable projection of a normalized sealed value,
declared over exactly one seal or one sealed field of a record. Its seal ID
domain-separates it; the record does not, since a query cannot know it. It
deliberately reveals equality and frequency among values under the same keys.
The application derives it from the same value it seals and writes both in one
statement; a record's `seal` derives both for its fields.

**Candidate**:
A row selected by a probe that still requires authenticated decryption and
normalized plaintext comparison before acceptance as a match.
<!-- Agent guidance: avoid “match” before authenticated decryption and normalized plaintext comparison. -->

**Ciphertext**:
The encrypted bytes of a value: the envelope that a sealed value wraps.
Structurally valid ciphertext has not necessarily been authenticated.
<!-- Agent guidance: in the typed API, say “sealed value” (`Sealed<F>`); “ciphertext” is the byte-level envelope. Avoid “encrypted value” for plaintext-bearing types. -->

**Context**:
What an envelope binds a value to: bytes that key derivation and the AAD both
take, never stored, plus a context fingerprint in the header. A sealed value's
seal context is its seal ID followed by the parts of its `Context`, the second
parameter of `Sealed<F, C>`: none for a standalone value (`()`), the record ID
for a record's field (`InRecord<K>`). Opening under another seal, context, or
record fails. Tenants are kept apart by keys, not by the context.
<!-- Agent guidance: “binding” is retired as a concept above the envelope (ADR-0011): say “context”, or “seal context” for the bytes; `Context` names a kind of context that adds parts after the seal ID (ADR-0012), and `ContextKind` is `()` or a `Context`. “Binding arguments” (`Args`), “bound value”, “bound ID type”, and “partition” are retired, as “scope”, “view”, and “keys view” were (ADR-0010). “Part” returns only for the library-owned parts of a context (ADR-0012). Applications never write context bytes. -->

**Context fingerprint**:
A public 8-byte truncated SHA-256 over a context's kind, never its values.
Every envelope header stores it; opening compares it before any key lookup to
report a context mismatch. Security never depends on it
(`envelope::CiphertextInfo::context_fingerprint`).
<!-- Agent guidance: “binding fingerprint” and “shape fingerprint” are retired names; do not reintroduce them. -->

**Current generation**:
The generation selected for new encryption or new stored blind indexes.

**Custody**:
Which keyring's root material protects which values: an application decision
the library neither records nor checks, so sealing under the wrong keyring
succeeds. A keyring per tenant keeps tenants apart. Test it; see
[choosing keyrings](guide.md#choosing-keyrings).
<!-- Agent guidance: custody as a declared part of a binding (keys views, typed key sources) is retired by ADR-0010 and reserved for a follow-up, which may return it as keys that carry their owner. Custody is about whose keys, not about access control or storage location. -->

**Default codec**:
The codec a derived seal uses when it names none. Only `String` and
`Secret<String>` (UTF-8) and `Vec<u8>` and `Secret<Vec<u8>>` (raw bytes) have
one, permanently and independent of features; a seal over any other value type
names its codec. A `transparent` seal stores its single field with that field's
codec.
<!-- Agent guidance: “plaintext type” and the `Plaintext` trait are retired (ADR-0007); no application or dependency can declare or change a default codec. -->

**Index context**:
The context a blind index is derived under: its seal ID alone, without a
record.
<!-- Agent guidance: “index binding”, “index scope”, and “partition” are retired. -->

**Index handle**:
A const a record declares for each of its blind indexes, named after its column,
such as `Customer::EMAIL_INDEX` (`Index`): its `probes` derive a lookup's
probes, and its `open_matching` opens the candidate rows and keeps the matches.

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Installed keys**:
The process-wide keys set once with `keys::install` and never replaced. They
serve only standalone values. Only the automatic column reads them, and fails
with `KeysNotInstalled` before installation; every operation takes keys
explicitly.
<!-- Agent guidance: avoid “global column keys” or “global keyring”; the global is the installed keys. -->

**Key generation**:
An immutable pairing of a generation identifier and root key material. Encryption
and blind-index generations are separate roles with independently generated keys.

**Keyring**:
The current key generation of one key role plus the previous generations that
stored data still needs (`EncryptionKeyring`, `BlindIndexKeyring`); `Keys`
pairs the two roles. Operations take the keyring, or `Keys`, to use. Key IDs are
generated UUIDs, unique within a keyring and never shared across keyrings, so
opening with the wrong keyring fails loudly.
<!-- Agent guidance: “key source” (`EncryptionKeySource`, `BlindIndexKeySource`) is retired (ADR-0010), as “key provider”, `Router`, and “route” are (ADR-0006): choosing which keyring protects which values is application code. -->

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
<!-- Agent guidance: avoid “authentication” or “integrity verification” for a generation-only check. -->

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison. It is persistent schema;
the normalizer name (`BlindIndexSpec::NORMALIZER`) identifies its rules.

**Part**:
A typed value a context adds after the seal ID: its kind code, which names
the part and how its value is encoded, and the length-prefixed value. The
record ID is the only part. Applications never declare parts; a `Context` does.
<!-- Agent guidance: this is not the retired application-declared part of ADR-0005 to ADR-0010 (`#[part]`, `PartId`, `part_id!`), which stays retired; never suggest that applications add parts. Parts have no slot or part ID. -->

**Plain value**:
A plaintext value of a seal held by the automatic SQLx column (`Plain<F>`),
which seals it on encode and opens it on decode with the installed keys. A
column decoder does not see the row, so it serves only standalone values and
writes no blind indexes.
<!-- Agent guidance: `Plain` is the only plaintext-typed column; a record's fields and values of indexed seals are sealed explicitly. `Encrypted<F>` is the retired name of the plaintext carrier; do not reintroduce it. Column keys (`Plain<F, K>`, `ColumnKeys`, `GlobalKeys`) and “key context” are retired: the column reads the installed keys. -->

**Probe**:
A blind-index lookup value for one readable index-key generation. A lookup uses
all probes to cover the readable generations.

**Readable generation**:
A generation available for decryption or blind-index probing, including the
current generation and any staged or retained generations. A readable generation
may be staged before first use.
<!-- Agent guidance: avoid “old key”; a readable generation may be staged before first use. -->

**Record**:
A row that stores its record ID beside its sealed fields (`Record`). Every field
is the record ID, a sealed field, or plaintext. Each sealed field has its own
seal and is sealed in `InRecord<K>`, so a value moved to another field or row
fails to open. The record ID is stored in plaintext and authenticated on open;
plaintext fields, such as an org, are not, so the application authorizes on them.
`#[derive(Record)]` generates the stored form, a seal per sealed field, and an
index handle per blind index.
<!-- Agent guidance: a “record” is the whole row, and its “fields” are the struct's members. `Recorded<S, Id>`, `Seal::Record`, and `Seal::RECORD` are retired: a record is a context layered over its fields' seals (ADR-0012), which know nothing of it. Avoid “entity” or “model” for a record. -->

**Record ID**:
The ID of the row a record's fields are stored in, generated by the client
before the values are sealed: a `Uuid` or `[u8; 16]`, an `i64`, or bytes
(`Vec<u8>`, `Box<[u8]>`). Its kind is part of the seal context.

**Schema manifest**:
A reviewable listing of registered seals, blind indexes, and records with their
persistent schema: IDs, codec, padding, context fingerprints, precision,
normalizer, and a record's seals and plaintext fields (by name). It names IDs,
never Rust types, so its output is stable across toolchains. Applications
compare it with a committed snapshot in CI.
<!-- Agent guidance: the codec ID and normalizer name are reported, never stored in ciphertext or indexes. Custody labels and the shred unit are retired with keys views (ADR-0010); `testing::assert_sealed_under` is how an application tests its choice of keys. -->

**Seal**:
A type that declares how its values are sealed (`Seal`): its seal ID, value
type, codec, and padding. It declares no blind indexes: those are declared over
it (`BlindIndexSpec`) or on a record's sealed field. A value sealed with one
seal does not open as another. A seal is either a marker over a separate value
type, so one value type can back several seals (a home and a billing address),
or its own value (a self-valued seal), such as `struct UserEmail(String)`. A seal
knows nothing of the context its values are sealed in.
<!-- Agent guidance: “field” is the retired name for a seal (ADR-0007) and now means only a member of a struct or record; “profile” is older still. Do not reintroduce either. Avoid “column”, “key”, or “cipher suite” as synonyms: a seal is independent of database names. -->

**Seal ID**:
The stable identity of a seal, independent of Rust and database names. Seals
that declare the same seal ID can read each other's ciphertext; a different
seal ID fails authentication.

**Sealed value**:
A value encrypted under a seal's context (`Sealed<F, C>`, `Sealed<F>` for a
standalone value). Sealing encodes, pads, and encrypts; opening authenticates
and returns the bare value. `seal_in` and `open_in` take the context's value,
such as the record ID. Parsing checks structure only.
<!-- Agent guidance: `Ciphertext<F>` is the retired name; say “seal” and “open”, not “encrypt” and “decrypt”, for the typed operations. -->

**Shredding**:
Destroying root keys, which makes every value sealed under them unreadable. What
can be shredded on its own is decided by how the application keeps root keys:
with a keyring per org, one org. Values that share keys, such as the workspaces
of an org, are never shredded on their own.
<!-- Agent guidance: “shred unit” was the manifest's report of a keys view (ADR-0009); keys views are retired, so say what the application's keyrings allow. -->

**Standalone value**:
A sealed value bound to its seal ID alone (`Sealed<F>`), as opposed to a
record's field, which is also bound to the record ID. `Sealed::seal` and `open`
serve standalone values; a record seals and opens its own fields.
<!-- Agent guidance: “standalone seal” is the older name; a seal itself knows nothing of where its values are stored (ADR-0012), so “standalone” describes a value, not a seal. -->

**Stored form**:
The form of a record as it is stored (`Record::Stored`, `Stored{Record}` by
default): its record ID and plaintext fields as they are, each sealed field as
its sealed value, and a blind-index column after each indexed field.
`#[cryptbox(stored(…))]` names it and forwards attributes to it, such as
`derive(sqlx::FromRow)`.
<!-- Agent guidance: “sealed struct” is the retired name, and `Sealed{Record}` its old default. -->

**Suite**:
A complete encryption construction identified by a suite ID, specifying key
derivation, authenticated encryption, and how metadata and context are authenticated.

**Value type**:
The application's own type whose values a seal seals. It says how it encodes,
never where it is stored: identity belongs to the seal. A self-valued seal is
both at once, so it is never shared by another seal.
<!-- Agent guidance: avoid giving a shared value type a seal ID; the same value type routinely backs several seals. -->
