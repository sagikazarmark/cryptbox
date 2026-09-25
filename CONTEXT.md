# CryptBox

Canonical language for application-layer encrypted storage. This glossary is an
explanation of the current model; the [concepts guide](docs/concepts.md) connects
the terms to the public API and the [task index](docs/README.md) supplies next steps.

## Language

**Profile**:
A policy for an application value's encoding, padding, binding, and key context.
_Avoid_: Key, cipher suite

**Binding**:
The expected cryptographic domain of a value, independent of where its stored
bytes are found. Field binding identifies a logical field, not a row or tenant.

**Unit context**:
A binding context with no runtime information. It does not mean that a value is
unbound, and it does not supply keys.

**Key context**:
The policy-selected access point to encryption and blind-index key providers.
_Avoid_: Binding context

**Key provider**:
A source of current and readable key generations for one key role.

**Key generation**:
An immutable pairing of a generation identifier and root key material. Encryption
and blind-index generations are separate roles with independently generated keys.

**Current generation**:
The generation selected for new encryption or new stored blind indexes.

**Readable generation**:
A generation available for decryption or blind-index probing, including the
current generation and any staged or retained generations.
_Avoid_: Old key (a readable generation may be staged before first use)

**Ciphertext**:
The encrypted stored representation of a value. Structurally valid ciphertext
has not necessarily been authenticated.
_Avoid_: Encrypted value (when referring to the plaintext-bearing application wrapper)

**Blind index**:
A separately keyed, truncated searchable projection of a normalized value.
It deliberately reveals equality and frequency information.

**Normalization**:
The application-defined conversion that gives equivalent values the same bytes
for blind-index derivation and candidate comparison.

**Index precision**:
The number of retained blind-index bits. Fewer bits increase false candidates
and obscure equality more, without eliminating index leakage.

**Probe**:
A blind-index lookup value for one readable index-key generation. A lookup uses
all probes to cover the readable generations.

**Candidate**:
A row selected by a probe that still requires authenticated decryption and
normalized plaintext comparison before acceptance as a match.
_Avoid_: Match (before comparison)

**Prepared storage**:
Ciphertext and optional blind indexes derived from the same source value, ready
for an application-owned atomic write. Preparation is not persistence.

**Migration-state verification**:
Inspection of stored structure and generation convergence. It is distinct from
authenticated readability and from stored-index consistency.
_Avoid_: Authentication, integrity verification (for a generation-only check)
