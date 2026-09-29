# Glossary

**Binding**:
The expected cryptographic domain of a value, independent of where its stored
bytes are found. Every sealed value is bound at runtime to its seal ID, to the
values of its seal's declared scope, and, when the seal declares `RECORD`, to a
record ID. A field-only binding (`FieldOnly`) identifies a seal alone, not a
row or tenant. The binding's *declaration* (its parts and whether it binds a record) is
persistent schema, declared by the seal; its values are supplied at each call as
the seal's binding arguments (`Args`). Opening under other values fails
authentication; opening under another declaration reports a binding mismatch.
<!-- Agent guidance: “binding” is the whole domain; “scope” is the declared parts; “key scope” is only the `keys` parts. Avoid “context” for any of them: it names only the envelope's input (see Context), and a user-authored context was rejected in ADR-0005. -->

**Binding arguments**:
The binding values of one sealing or opening call, typed by the seal (`Args<F>`):
`()` for a `FieldOnly` seal, `RecordId` for a `FieldOnly` seal that binds a record,
`&F::Binding`, or `(&F::Binding, RecordId)`. A missing or extra record fails the
build. Within a record, `InRecord(&F::Binding, RecordId)` binds the record
exactly when the seal declares one.

**Binding fingerprint**:
A public 8-byte summary of a binding's declaration: truncated SHA-256 over its
part IDs, kinds, and roles and whether it binds a record, never its values.
Every envelope header stores the fingerprint of the binding it was sealed
under, and opening compares it with the reader's before any key lookup,
reporting a binding mismatch. Equal fingerprints do not imply equal bindings,
and security never depends on the fingerprint.
<!-- Agent guidance: “shape” is the retired name for a binding's declaration, and “shape fingerprint” for this; do not reintroduce them. -->

**Binding part**:
One declared value of a binding scope, with a part ID, a value kind (uuid, i64,
or bytes), and a role. A `keys` part scopes key custody and blind indexes, an
`index` part scopes blind indexes only, and any other part is bound only. A
record ID is never a part: it is always bound only.

**Blind index**:
A separately keyed, truncated searchable projection of a normalized sealed value.
Each blind index is declared over exactly one seal. Its seal ID and its
index arguments (`IndexArgs`, the values of the binding's `keys` and `index`
parts) domain-separate it; bound-only parts and the record do not, since a
query cannot know them. It deliberately reveals equality and frequency information.

**Candidate**:
A row selected by a probe that still requires authenticated decryption and
normalized plaintext comparison before acceptance as a match.
<!-- Agent guidance: avoid “match” before authenticated decryption and normalized plaintext comparison. -->

**Ciphertext**:
The encrypted bytes of a value: the envelope that a sealed value wraps.
Structurally valid ciphertext has not necessarily been authenticated.
<!-- Agent guidance: in the typed API, say “sealed value” (`Sealed<F>`); “ciphertext” is the byte-level envelope. Avoid “encrypted value” for plaintext-bearing types. -->

**Column keys**:
The key source of an automatic SQLx column, named in its type as
`Plain<F, K>` (`ColumnKeys`): the installed keys (`GlobalKeys`, the default) or
an application-owned static `Keys`. It belongs to the column type, not to a
seal.
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
Which keyring's root material protects a seal's values in a key scope. It is an
application decision that the library neither records nor checks: sealing under
the wrong keyring succeeds. Record it per seal and key scope, and test it; see
[choosing keyrings](choosing-keyrings.md).
<!-- Agent guidance: custody is about whose keys, not about access control or storage location. Sealing with the wrong keyring is a silent write-time error, not an authentication failure. -->

**Seal**:
A type that declares how its values are sealed (`Seal`): its seal ID, value
type, codec, padding, binding scope, whether it binds a record, and its blind
indexes. A value sealed with one seal does not open as another. A seal is
either a marker over a separate value type, so one value type can back several
seals, such as a home and a billing address, each with its own seal ID; or its
own value (a self-valued seal), such as `struct UserEmail(String)`. Seals serve
any sealed value: a database column, a message, or a whole response.
<!-- Agent guidance: “field” is the retired name for a seal (ADR-0007) and now means only a member of a struct or record; “profile” is older still. Do not reintroduce either. Avoid “column”, “key”, or “cipher suite” as synonyms: a seal is independent of database names. -->

**Seal ID**:
The stable identity of a seal, independent of Rust and database names. Seals
that declare the same seal ID can read each other's ciphertext; a different
seal ID fails authentication.

**Index binding**:
The binding a blind index is derived under: the seal ID and the values of the
binding's `keys` and `index` parts, without bound-only parts or a record. A
query supplies it as the index arguments (`IndexArgs`); a prepared value takes
it from the binding it was sealed with. A seal without `keys` or `index`
parts has a field-only index binding.
<!-- Agent guidance: code calls the encoded form the index domain (`BindingDomain::index`), as it calls a binding's encoding `BindingDomain`; say “index binding” in prose. Avoid “index scope”, which blurs it with the key scope. -->

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Installed keys**:
The process-wide keys set once with `keys::install` and never replaced. They
serve only `FieldOnly` seals without a record. The global conveniences
(`seal_global()`, `open_global()`, `with_index()`, `probes()`) and the automatic
column read them and fail with `KeysNotInstalled` before installation; every
other operation takes keys explicitly.
<!-- Agent guidance: avoid “global column keys” or “global keyring”; the global is the installed keys. -->

**Key generation**:
An immutable pairing of a generation identifier and root key material. Encryption
and blind-index generations are separate roles with independently generated keys.

**Key scope**:
The `keys` parts of a binding, which key custody follows (`KeyScope`). Bindings
with equal `keys` values share a key scope whatever their other parts; a binding
without `keys` parts has the empty key scope.

**Key source**:
What an operation takes its keys from (`EncryptionKeySource`,
`BlindIndexKeySource`). The operation passes it the seal or index and the key
scope; a keyring and `Keys` ignore both and return themselves, and an
application source may pick a keyring by either.
<!-- Agent guidance: “key provider”, `Router`, and “route” are retired (ADR-0006); choosing which keyring protects a seal is application code, not library routing. -->

**Keyring**:
The current key generation of one key role plus the previous generations that
stored data still needs (`EncryptionKeyring`, `BlindIndexKeyring`); `Keys`
pairs the two roles. Key IDs are generated UUIDs, unique within a keyring and
never shared across keyrings, so opening with the wrong keyring fails loudly.

**Legacy-binding window**:
The bounded period in which a seal's values may still be sealed with the
binding declaration it had before a declaration change. Readers open both
declarations and probe both index bindings, and a sweep reseals the old
declaration, recognized by the binding fingerprint in each header. The window
closes once a complete verification pass counts no such rows.
<!-- Agent guidance: distinct from legacy data, which is not a CryptBox envelope at all (`RowState::Legacy`); a legacy-binding row is a valid envelope of an older declaration (`RowState::LegacyBinding`). -->

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
<!-- Agent guidance: avoid “authentication” or “integrity verification” for a generation-only check. -->

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison. It is persistent schema;
the normalizer name (`BlindIndexSpec::NORMALIZER`) identifies its rules.

**Object key**:
The canonical text form of a binding's index arguments that keys a Restate
Virtual Object (`restate::ObjectKey`): the `keys` parts, then the `index`
parts, each spelled exactly one way. Every object key of a key scope starts
with that scope's prefix. It is plaintext to Restate, and it names a scope
only as far as its caller was authorized for it.
<!-- Agent guidance: “object key” is Restate's term for the key of a Virtual Object; do not call it a “key” alone, which reads as key material. -->

**Plain value**:
A plaintext value of a seal held by the automatic SQLx column (`Plain<F, K>`),
which seals it on encode and opens it on decode. A column decoder sees neither a
row nor a scope, so it serves only `FieldOnly` seals without a record or blind
indexes.
<!-- Agent guidance: `Plain` is the only plaintext-typed column; values of bound or indexed seals are sealed explicitly. `Encrypted<F>` is the retired name of the plaintext carrier; do not reintroduce it. -->

**Plaintext type**:
A value type that names a default codec. `String` and `Secret<String>` default
to UTF-8, and `Vec<u8>` and `Secret<Vec<u8>>` to raw bytes; these defaults
are permanent. Any other value type names its codec explicitly or declares its
own default.

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
A row whose sealed fields are sealed and opened together under one binding
and the row's record ID (`Record`). The record ID is never encrypted: each seal
that declares `RECORD` binds it, so it must be readable before the row is
opened. The sealed form holds each sealed field's value and the blind indexes
its seal declares; `#[derive(Record)]` rejects a record that omits one.
<!-- Agent guidance: a “record” is the whole row, and its “fields” are the struct's members; a seal “binds a record” when it declares `RECORD`. `InRecord` passes the record ID to every seal and binds it only where declared. Avoid “entity” or “model” for a record. -->

**Schema manifest**:
A reviewable listing of registered seals and blind indexes with their
persistent schema: seal ID, codec ID, padding, record flag, binding declaration
(fingerprint, parts, kinds, and roles), shred unit, index ID, precision, and
normalizer name. It names IDs, never Rust types, so its output is the same on
every toolchain. A seal may carry a custody label, a declarative note of which
keys the application passes for it.
Applications compare it with a committed snapshot in CI.
<!-- Agent guidance: the codec ID and normalizer name are reported, never stored in ciphertext or indexes. A custody label is documentation, not routing: choosing keyrings stays application code (ADR-0006), and `testing::assert_sealed_under` is how an application tests that choice. -->

**Scope**:
The declared parts of a binding, such as a tenant, or an org plus a workspace
(`Binding`). Parts have roles: `keys` parts form the key scope, `index` parts
also scope blind indexes, and other parts are bound only. A scope struct owns
its values; a record is never part of it.

**Sealed value**:
A value encrypted under a seal and bound to its binding (`Sealed<F>`).
Sealing encodes, pads, and encrypts; opening authenticates under the same binding
arguments and returns the bare value. Parsing a sealed value checks structure
only.
<!-- Agent guidance: `Ciphertext<F>` is the retired name; say “seal” and “open”, not “encrypt” and “decrypt”, for the typed operations. -->

**Shred unit**:
The finest `keys` part whose root keys are stored independently. Destroying
those root keys makes every value sealed under them unreadable; bound-only and
`index` parts are never shredded on their own. The schema manifest reports the
finest possible unit, the key scope (all `keys` parts, or the whole keyring
when there are none), since only the application knows how its root keys are
stored.
<!-- Agent guidance: the manifest's shred unit assumes root keys per key scope; a coarser application choice belongs in the seal's custody label. -->

**Suite**:
A complete encryption construction identified by a suite ID, specifying key
derivation, authenticated encryption, and how metadata and binding are authenticated.

**Value type**:
The application's own type whose values a seal seals. It says how it encodes,
never where it is stored: identity belongs to the seal. A self-valued seal is
both at once, so it is never shared by another seal.
<!-- Agent guidance: avoid giving a shared value type a seal ID; the same value type routinely backs several seals. -->
