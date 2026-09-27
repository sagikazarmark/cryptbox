# Glossary

**Binding**:
The expected cryptographic domain of a value, independent of where its stored
bytes are found. Every value is bound to its field ID. Field binding identifies a
logical field, not a row or tenant.

**Blind index**:
A separately keyed, truncated searchable projection of a normalized value.
It deliberately reveals equality and frequency information.

**Candidate**:
A row selected by a probe that still requires authenticated decryption and
normalized plaintext comparison before acceptance as a match.
<!-- Agent guidance: avoid “match” before authenticated decryption and normalized plaintext comparison. -->

**Ciphertext**:
The encrypted stored representation of a value. Structurally valid ciphertext
has not necessarily been authenticated. Ciphertext is distinct from the
plaintext-bearing application wrapper.
<!-- Agent guidance: avoid “encrypted value” when referring to the plaintext-bearing application wrapper. -->

**Current generation**:
The generation selected for new encryption or new stored blind indexes.

**Field**:
A marker type that declares one logical encrypted field: its field ID, value
type, codec, and padding. One value type can back several fields, such as a
home and a billing address, each with its own field ID.
<!-- Agent guidance: “profile” is the retired name for a field; do not reintroduce it. Avoid “column”, “key”, or “cipher suite” as synonyms: a field is a logical location, independent of database names. -->

**Field ID**:
The stable identity of a logical encrypted field, independent of Rust and
database names. Fields that declare the same field ID can read each other's
ciphertext; a different field ID fails authentication.

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Key context**:
The process-wide access point to encryption and blind-index key providers used
by operations that do not take keys explicitly. It belongs to the process, not
to a field.
<!-- Agent guidance: avoid “binding context” as a synonym. -->

**Key generation**:
An immutable pairing of a generation identifier and root key material. Encryption
and blind-index generations are separate roles with independently generated keys.

**Key provider**:
A source of current and readable key generations for one key role. Every request
names the field it serves; a provider that serves all fields alike may ignore it.

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
<!-- Agent guidance: avoid “authentication” or “integrity verification” for a generation-only check. -->

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison.

**Plaintext type**:
A value type that names a default codec. `String` and `Secret<String>` default
to UTF-8, and `Vec<u8>` and `Secret<Vec<u8>>` to raw bytes; these defaults
are permanent. Any other value type names its codec explicitly or declares its
own default.

**Prepared storage**:
Ciphertext and optional blind indexes derived from the same source value, ready
for an application-owned atomic write. Preparation is not persistence.

**Probe**:
A blind-index lookup value for one readable index-key generation. A lookup uses
all probes to cover the readable generations.

**Readable generation**:
A generation available for decryption or blind-index probing, including the
current generation and any staged or retained generations. A readable generation
may be staged before first use.
<!-- Agent guidance: avoid “old key”; a readable generation may be staged before first use. -->

**Route**:
The assignment of a field ID to the key provider that protects it. Routes are
deployment configuration, not persistent schema: the envelope records the key
ID, so a field can move to another provider that resolves the same generations.
A strict router rejects unrouted fields; a fallback router serves them from a
default provider and reports that it does.
<!-- Agent guidance: avoid “falls back” for strict routers; they reject unrouted fields. -->

**Suite**:
A complete encryption construction identified by a suite ID, specifying key
derivation, authenticated encryption, and how metadata and binding are authenticated.

**Value type**:
The application's own type whose values are stored in a field. It says how it
encodes, never where it is stored: identity belongs to the field.
<!-- Agent guidance: avoid giving a value type a field ID; the same value type routinely lives in several fields. -->
