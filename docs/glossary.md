# Glossary

**Binding**:
The expected cryptographic domain of a value, independent of where its stored
bytes are found. Every sealed value is bound at runtime to its seal ID, to its
bound values, and, when its seal binds a record, to the ID of the record it is
stored in. The binding of a seal without bound values or a record identifies the
seal alone, not a row or tenant. The binding's *declaration* (the kinds of its
bound values, and whether it binds a record) is persistent schema, declared by
the seal; its values come from the row, for a record, or are supplied at each
call as the seal's binding arguments (`Args`). Opening under other values fails
authentication; opening under another declaration reports a binding mismatch.
<!-- Agent guidance: “binding” is the whole domain. “Scope”, “part”, “view”, and “keys view” are retired (ADR-0010): say “bound values” and “bound ID types”. Avoid “context” for a binding: it names only the envelope's input (see Context), and a user-authored context was rejected in ADR-0005. -->

**Binding arguments**:
The binding values of one sealing or opening call of a standalone value, typed by
the seal (`Args<F>`): its bound values in the order of its bound ID types, then
its record ID when it binds one: `()`, `&org`, `(&org, &workspace)`, or
`(&org, &id)`. A value of another type, or a missing or extra record, is a type
error. A record passes its own bound values and record ID.

**Binding fingerprint**:
A public 8-byte summary of a binding's declaration: truncated SHA-256 over the
part IDs and kinds of its bound values and whether it binds a record, never its
values. Every envelope header stores the fingerprint of the binding it was
sealed under, and opening compares it with the reader's before any key lookup,
reporting a binding mismatch. Equal fingerprints do not imply equal bindings,
and security never depends on the fingerprint.
<!-- Agent guidance: “shape” is the retired name for a binding's declaration, and “shape fingerprint” for this; do not reintroduce them. The role byte is always `03`: roles are retired. -->

**Blind index**:
A separately keyed, truncated searchable projection of a normalized sealed value.
Each blind index is declared over exactly one seal, or on one sealed field of a
record. Its seal ID and the values of its partition domain-separate it; the
bound values it spans and the record do not, since a query cannot know them. It
deliberately reveals equality and frequency information.

**Bound ID type**:
An application's own ID type whose values are bound, such as `OrgId` (`BoundId`).
Its kind ID names the kind of value once, on the type: every value of it is bound
under that part ID, whichever seal or record binds it. `#[derive(BoundId)]`
declares one over a UUID, an `i64`, or bytes; `TenantId` is a ready-made one. A
seal names its bound ID types as a list, `Seal::Bound`, such as
`(OrgId, WorkspaceId)`.
<!-- Agent guidance: “anchor” was considered and rejected (it reads as a PKI trust anchor); do not use it. -->

**Bound value**:
A value a sealed value is bound to, such as the org and workspace it belongs to:
a value of a bound ID type. A record stores its bound values as its own
columns, and opening authenticates them: a changed column or a value copied from
another row fails to open. A bound value says where a value belongs, not who may
read it; the caller authorizes on it.
<!-- Agent guidance: prefer “bound value” to “scope value” or “part value”; `PartValue` is the low-level encoding of one. -->

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
to use, and sealing under the wrong keyring succeeds. Test it; see
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
The binding a blind index is derived under: the seal ID and the values of its
partition, without a record. A query supplies the partition; a stored index
takes it from the bound values its value was sealed under. An index without a
partition has an unpartitioned index binding.
<!-- Agent guidance: code calls the encoded form the index domain (`BindingDomain::index`), as it calls a binding's encoding `BindingDomain`. “Index scope” is the retired name of the partition. -->

**Index handle**:
A const a record declares for each of its blind indexes, named after its column,
such as `Customer::EMAIL_INDEX` (`Index`): its `probes` derive a lookup's
probes in a partition, and its `open_matching` opens the candidate rows and keeps
the matches, refusing rows of another partition before decrypting them.

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Installed keys**:
The process-wide keys set once with `keys::install` and never replaced. They
serve only seals without bound values or a record. The global conveniences
(`seal_global()`, `open_global()`, `with_index()`, `probes()`) and the automatic
column read them and fail with `KeysNotInstalled` before installation; every
other operation takes keys explicitly.
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
binding declaration it had before a declaration change. Readers open both
declarations and probe both index bindings, and a sweep reseals the old
declaration, recognized by the binding fingerprint in each header. A record
field names its old declaration with `legacy(…)`, and the schema manifest lists
the open window. The window closes once a complete verification pass counts no
such rows.
<!-- Agent guidance: distinct from legacy data, which is not a CryptBox envelope at all (`RowState::Legacy`); a legacy-binding row is a valid envelope of an older declaration (`RowState::LegacyBinding`). -->

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
<!-- Agent guidance: avoid “authentication” or “integrity verification” for a generation-only check. -->

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison. It is persistent schema;
the normalizer name (`BlindIndexSpec::NORMALIZER`) identifies its rules.

**Partition**:
The bound values that partition a blind index (`BlindIndexSpec::Partition`):
all of its seal's bound values except those it spans, named with `across(…)` on
a record field. A query supplies them; equal values in other partitions derive
unrelated index bytes. Two indexes over one seal may partition differently.
<!-- Agent guidance: “index scope” is the retired name (ADR-0010), and the `index` part role and `IndexArgs` are older still; do not reintroduce them. -->

**Plain value**:
A plaintext value of a seal held by the automatic SQLx column (`Plain<F, K>`),
which seals it on encode and opens it on decode. A column decoder sees neither a
row nor its bound values, so it serves only seals without bound values, a
record, or blind indexes.
<!-- Agent guidance: `Plain` is the only plaintext-typed column; values of bound or indexed seals are sealed explicitly. `Encrypted<F>` is the retired name of the plaintext carrier; do not reintroduce it. -->

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
A row that stores its record ID and bound values beside its sealed fields
(`Record`). Every field has one role: the record ID, a bound value, a sealed
field, or plaintext. Each sealed field has its own seal and is bound to it, to
all of the record's bound values, and to the record ID, so a value moved to
another field, org, or row fails to open. The record ID and bound values are
never encrypted: opening reads them from the row and authenticates them.
`#[derive(Record)]` generates the stored form, a seal per sealed field, and an
index handle per blind index. The schema manifest lists a record's plaintext
fields by name.
<!-- Agent guidance: a “record” is the whole row, and its “fields” are the struct's members. `Recorded<S, Id>` is retired: a seal binds a record by naming its record ID's type, `Seal::Record`. Avoid “entity” or “model” for a record. -->

**Schema manifest**:
A reviewable listing of registered seals, blind indexes, and records with their
persistent schema: seal ID, codec ID, padding, record kind, binding declaration
(fingerprint, and each bound value's part ID and kind), index ID, precision,
normalizer name, partition, and a record's seals, record ID, bound, plaintext
fields, and open legacy windows. It names IDs, never Rust types, so its output is
the same on every toolchain; a record's fields, which have no ID, are listed by
name. Applications compare it with a committed snapshot in CI.
<!-- Agent guidance: the codec ID and normalizer name are reported, never stored in ciphertext or indexes. Custody labels and the shred unit are retired with keys views (ADR-0010); `testing::assert_sealed_under` is how an application tests its choice of keys. -->

**Seal**:
A type that declares how its values are sealed (`Seal`): its seal ID, value
type, codec, padding, bound ID types, whether it binds a record, and its blind
indexes. A value sealed with one seal does not open as another. A seal is
either a marker over a separate value type, so one value type can back several
seals, such as a home and a billing address, each with its own seal ID; or its
own value (a self-valued seal), such as `struct UserEmail(String)`. Seals serve
any sealed value: a database column, a message, or a whole response. A record
declares a seal for each of its sealed fields.
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
with a keyring per org, one org. Bound values that share keys, such as the
workspaces of an org, are never shredded on their own.
<!-- Agent guidance: “shred unit” was the manifest's report of a keys view (ADR-0009); keys views are retired, so say what the application's keyrings allow. -->

**Stored form**:
The form of a record as it is stored (`Record::Stored`, `Stored{Record}` by
default): its record ID, bound values, and plaintext fields as they are, each
sealed field as its sealed value, and a blind-index column after each indexed
field. `#[cryptbox(stored(…))]` names it and forwards attributes to it, such as
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
