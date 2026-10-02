# Glossary

**Binding**:
The expected cryptographic domain of a value, independent of where its stored
bytes are found. Every sealed value is bound at runtime to its seal ID and, for a
field of a record, to the ID of the record it is stored in, which the record
reads from the row. A standalone seal's binding identifies the seal alone, not a
row or tenant. The binding's *declaration* (whether it binds a record ID, and its
kind) is persistent schema. Opening under another record fails authentication;
opening under another declaration reports a binding mismatch. The binding is
private to the library: no call takes binding arguments. Tenants are kept apart
by keys, not by the binding.
<!-- Agent guidance: “binding” is the whole domain; “binding arguments” (`Args`) are retired (ADR-0011). “Bound value”, “bound ID type”, and “partition” are retired (ADR-0011), as “scope”, “part”, “view”, and “keys view” were (ADR-0010); do not reintroduce them. Avoid “context” for a binding: it names only the envelope's input (see Context), and a user-authored context was rejected in ADR-0005. -->

**Binding fingerprint**:
A public 8-byte summary of a binding's declaration: truncated SHA-256 over
whether it binds a record ID and its kind, never its value. Every
envelope header stores the fingerprint of the binding it was sealed under, and
opening compares it with the reader's before any key lookup, reporting a binding
mismatch. Equal fingerprints do not imply equal bindings, and security never
depends on the fingerprint.
<!-- Agent guidance: “shape” is the retired name for a binding's declaration, and “shape fingerprint” for this; do not reintroduce them. -->

**Blind index**:
A separately keyed, truncated searchable projection of a normalized sealed value.
Each blind index is declared over exactly one seal, or on one sealed field of a
record. Its seal ID domain-separates it; the record does not, since a query
cannot know it. Equal values of one seal derive equal indexes under the same
keys, and unrelated ones under separate keys. It deliberately reveals equality
and frequency information.

**Candidate**:
A row selected by a probe that still requires authenticated decryption and
normalized plaintext comparison before acceptance as a match.
<!-- Agent guidance: avoid “match” before authenticated decryption and normalized plaintext comparison. -->

**Ciphertext**:
The encrypted bytes of a value: the envelope that a sealed value wraps.
Structurally valid ciphertext has not necessarily been authenticated.
<!-- Agent guidance: in the typed API, say “sealed value” (`Sealed<F>`); “ciphertext” is the byte-level envelope. Avoid “encrypted value” for plaintext-bearing types. -->

**Column keys**:
The keys of an automatic SQLx column, named in its type as `Plain<F, K>`
(`ColumnKeys`): the installed keys (`GlobalKeys`, the default) or an
application-owned static `Keys`. They belong to the column type, not to a seal.
<!-- Agent guidance: “key context” is the retired name; do not reintroduce it. -->

**Context**:
What an envelope binds a value to: bytes that key derivation and the AAD both
take, which are never stored, and a context fingerprint that the header
stores. The envelope interprets neither. For a sealed value, the context is
its binding's encoding and binding fingerprint;
`CiphertextInfo::context_fingerprint` reports the stored fingerprint.
<!-- Agent guidance: “context” is the envelope-level term only. For what a value is bound to, say “binding”; applications never write context bytes. -->

**Current generation**:
The generation selected for new encryption or new stored blind indexes.

**Custody**:
Which keyring's root material protects which values. It is an application
decision that the library neither records nor checks: operations take the keys
to use, and sealing under the wrong keyring succeeds. Keeping a keyring per
tenant is how tenants are kept apart. Test it; see
[choosing keyrings](choosing-keyrings.md).
<!-- Agent guidance: custody as a declared part of a binding (keys views, typed key sources) is retired by ADR-0010 and reserved for a follow-up, which may return it as keys that carry their owner. Custody is about whose keys, not about access control or storage location. -->

**Default codec**:
The codec a derived seal uses when it names none. Only `String` and
`Secret<String>` (UTF-8) and `Vec<u8>` and `Secret<Vec<u8>>` (raw bytes) have
one, permanently and independent of features; a seal over any other value type
names its codec. A `transparent` seal stores its single field with that field's
codec.
<!-- Agent guidance: “plaintext type” and the `Plaintext` trait are retired (ADR-0007); no application or dependency can declare or change a default codec. -->

**Index binding**:
The binding a blind index is derived under: its seal ID alone, the empty
binding, without a record.
<!-- Agent guidance: code calls the encoded form the index domain (`BindingDomain::index`), as it calls a binding's encoding `BindingDomain`. “Index scope” and “partition” are retired. -->

**Index handle**:
A const a record declares for each of its blind indexes, named after its column,
such as `Customer::EMAIL_INDEX` (`Index`): its `probes` derive a lookup's
probes, and its `open_matching` opens the candidate rows and keeps the matches.

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Installed keys**:
The process-wide keys set once with `keys::install` and never replaced. They
serve only standalone seals. The global conveniences (`seal_global()`,
`open_global()`, `with_index()`, `probes()`) and the automatic column read them
and fail with `KeysNotInstalled` before installation; every other operation
takes keys explicitly.
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

**Legacy-binding window**:
The bounded period in which a seal's values may still be sealed with the
binding declaration it had before a declaration change, such as moving into a
record. Readers open both declarations, and a sweep reseals the old one,
recognized by the binding fingerprint in each header. A record field names its
old declaration with `legacy(…)`, and the schema manifest lists the open window.
The window closes once a complete verification pass counts no such rows.
<!-- Agent guidance: distinct from legacy data, which is not a CryptBox envelope at all (`RowState::Legacy`); a legacy-binding row is a valid envelope of an older declaration (`RowState::LegacyBinding`). -->

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
<!-- Agent guidance: avoid “authentication” or “integrity verification” for a generation-only check. -->

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison. It is persistent schema;
the normalizer name (`BlindIndexSpec::NORMALIZER`) identifies its rules.

**Plain value**:
A plaintext value of a seal held by the automatic SQLx column (`Plain<F, K>`),
which seals it on encode and opens it on decode. A column decoder does not see
the row, so it serves only standalone seals without blind indexes.
<!-- Agent guidance: `Plain` is the only plaintext-typed column; a record's fields and values of indexed seals are sealed explicitly. `Encrypted<F>` is the retired name of the plaintext carrier; do not reintroduce it. -->

**Prepared storage**:
A sealed value and optional blind indexes derived from the same source value, ready
for an application-owned atomic write. Preparation is not persistence.

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
has one role: the record ID, a sealed field, or plaintext. Each sealed field has
its own seal and is bound to it and to the record ID, so a value moved to another
field or row fails to open. The record ID is never encrypted: opening reads it
from the row and authenticates it. Plaintext fields, such as an org, are not
authenticated: the application authorizes on them. `#[derive(Record)]`
generates the stored form, a seal per sealed field, and an index handle per
blind index. The schema manifest lists a record's plaintext fields by name.
<!-- Agent guidance: a “record” is the whole row, and its “fields” are the struct's members. `Recorded<S, Id>` and `Seal::Record` are retired: only a record binds its fields to its ID. Avoid “entity” or “model” for a record. -->

**Record ID**:
The ID of the row a record's fields are stored in, generated by the client
before the values are sealed: a `Uuid` or `[u8; 16]`, an `i64`, or bytes
(`Vec<u8>`, `Box<[u8]>`). Its kind is part of the binding declaration.

**Schema manifest**:
A reviewable listing of registered seals, blind indexes, and records with their
persistent schema: seal ID, codec ID, padding, record kind, binding fingerprint,
index ID, precision, normalizer name, and a record's seals, record ID, plaintext
fields, and open legacy windows. It names IDs, never Rust types, so its output is
the same on every toolchain; a record's fields, which have no ID, are listed by
name. Applications compare it with a committed snapshot in CI.
<!-- Agent guidance: the codec ID and normalizer name are reported, never stored in ciphertext or indexes. Custody labels and the shred unit are retired with keys views (ADR-0010); `testing::assert_sealed_under` is how an application tests its choice of keys. -->

**Seal**:
A type that declares how its values are sealed (`Seal`): its seal ID, value
type, codec, padding, and blind indexes. A value
sealed with one seal does not open as another. A seal is either a marker over a
separate value type, so one value type can back several seals, such as a home
and a billing address, each with its own seal ID; or its own value (a
self-valued seal), such as `struct UserEmail(String)`. Seals serve any sealed
value: a database column, a message, or a whole response. A record declares a
seal for each of its sealed fields, which only the record seals and opens.
<!-- Agent guidance: “field” is the retired name for a seal (ADR-0007) and now means only a member of a struct or record; “profile” is older still. Do not reintroduce either. Avoid “column”, “key”, or “cipher suite” as synonyms: a seal is independent of database names. -->

**Seal ID**:
The stable identity of a seal, independent of Rust and database names. Seals
that declare the same seal ID can read each other's ciphertext; a different
seal ID fails authentication.

**Sealed value**:
A value encrypted under a seal and bound to its binding (`Sealed<F>`).
Sealing encodes, pads, and encrypts; opening authenticates under the same binding
arguments and returns the bare value. Parsing a sealed value checks structure
only.
<!-- Agent guidance: `Ciphertext<F>` is the retired name; say “seal” and “open”, not “encrypt” and “decrypt”, for the typed operations. -->

**Shredding**:
Destroying root keys, which makes every value sealed under them unreadable. What
can be shredded on its own is decided by how the application keeps root keys:
with a keyring per org, one org. Values that share keys, such as the workspaces
of an org, are never shredded on their own.
<!-- Agent guidance: “shred unit” was the manifest's report of a keys view (ADR-0009); keys views are retired, so say what the application's keyrings allow. -->

**Standalone seal**:
A seal declared with `#[derive(Seal)]` or by hand, bound to its seal ID alone,
as opposed to the seal of a record's field. `Sealed::seal` and `open` serve
standalone seals; a record's field is sealed and opened by its record.

**Stored form**:
The form of a record as it is stored (`Record::Stored`, `Stored{Record}` by
default): its record ID and plaintext fields as they are, each sealed field as
its sealed value, and a blind-index column after each indexed field.
`#[cryptbox(stored(…))]` names it and forwards attributes to it, such as
`derive(sqlx::FromRow)`.
<!-- Agent guidance: “sealed struct” is the retired name, and `Sealed{Record}` its old default. -->

**Suite**:
A complete encryption construction identified by a suite ID, specifying key
derivation, authenticated encryption, and how metadata and binding are authenticated.

**Value type**:
The application's own type whose values a seal seals. It says how it encodes,
never where it is stored: identity belongs to the seal. A self-valued seal is
both at once, so it is never shared by another seal.
<!-- Agent guidance: avoid giving a shared value type a seal ID; the same value type routinely backs several seals. -->
