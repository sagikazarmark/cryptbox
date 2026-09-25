# From application values to stored bytes

**Explanation · current development model.** Use the [canonical glossary](../CONTEXT.md)
for definitions and the [task index](README.md) for procedures.

## The value lifecycle

`Encrypted<T, Profile>` contains **plaintext** in application memory, despite
its name. `expose_secret()` makes plaintext access deliberate. `Secret<T>` is
also a plaintext wrapper, without an encryption profile. Neither type is a
promise to erase arbitrary application-owned values.

A profile selects the codec (value to bytes), padding (encoded-length policy),
binding (expected cryptographic domain), and key context. `profile!` declares
that policy; `EncryptionProfile` is its expanded trait form. Encoding and
encryption produce `Ciphertext<T, Profile>`, the stored encrypted envelope.
Encrypting borrows the original value; it does not consume or erase it.
Parsing a ciphertext establishes structure, while decryption authenticates it.

`Prepared` borrows its source `Encrypted` value and holds ciphertext and optional
blind indexes derived from that value. The application must write the ciphertext
and each index atomically. Merely using an automatic SQLx encrypted column does
not maintain a separate index column.

## Binding context is not key context

The currently available bindings are **sealed** (applications cannot add their
own implementations): `Unbound` and `FieldBound<F>`.
Both use the unit context `()`. Thus `encrypt_with(&(), &keys)` can still be
field-bound: `&()` means no *runtime* binding information is needed, while the
profile supplies the stable field ID. `&keys` is the separate key provider.

`FieldBound<F>` authenticates the logical field for ciphertext and separates
blind-index derivation domains. It does not bind the row or tenant and does not
authenticate stored blind-index bytes. Copying a valid ciphertext between two
rows of the same field can still decrypt successfully. Applications cannot
implement a new `Binding`; row and tenant binding are future work in
[#23](https://github.com/sagikazarmark/cryptbox/issues/23) and
[#24](https://github.com/sagikazarmark/cryptbox/issues/24). Generic context-shaped
APIs do not imply those policies are currently available. Padding is also sealed
to the built-in policies; codecs, profiles, and key providers are extensible.

Context-less operations and automatic adapters obtain providers through the
profile's `KeyContext`. `GlobalKeyContext` is installed once per process and
cannot be reset. Explicit-provider methods use the provider passed by the
caller instead, which makes [parallel-independent tests](testing.md) practical.

## Generations and lookup

Each provider selects one current generation for writes and resolves readable
generations by exact ID. Keep each ID paired with the same material across
restarts; never reuse an ID with different material. Provision encryption and
blind-index root keys independently. The providers are synchronous; fetching
and refreshing secrets is the application's responsibility.

Readable generations include the current generation, retained generations, and
generations staged before writer promotion. A new current encryption key does
not rewrite existing ciphertext or revoke old keys. A new current index key
does not rewrite stored indexes either.

`blind_index_probes` supplies a probe for each readable index generation. Query
all probes, decrypt every candidate, and compare plaintext using the same
normalization policy before accepting it. Truncated indexes intentionally allow
false candidates; do not use them as uniqueness constraints. Candidate comparison
does not authenticate index metadata. See the [separate assurance procedures](stored-values.md#obtain-additional-assurance).

Next: check [persistent-schema rules](https://docs.rs/cryptbox/0.5.0/cryptbox/#persistent-schema),
then follow the [stored-value tutorial](stored-values.md).
