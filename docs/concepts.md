# How CryptBox works

CryptBox encrypts selected values inside your Rust application before they reach
storage. Your application works with an email address, for example, while the
database stores encrypted bytes. The application supplies the keys and decides
which fields to protect; CryptBox handles the conversion between values and their
encrypted representations.

This page follows one value through that process. To try it first, start with
[encrypt your first field](first-field.md). To evaluate whether this approach fits
your requirements, read the [security and threat model](security.md).

## The value lifecycle

Consider an email address represented by a Rust `String`:

```text
Application value → encode → optionally pad → encrypt → stored ciphertext
Application value ← decode ← remove padding ← authenticate and decrypt
```

Encoding turns the string into bytes. Optional padding conceals its exact encoded
length. Encryption then produces an **envelope** containing public metadata,
encrypted bytes, and an authentication tag. This envelope is the complete
ciphertext representation that can be stored in a database or serialized.

On the return path, CryptBox uses the envelope's key-generation ID to obtain the
right key and authenticates the ciphertext before returning plaintext. It then
removes any padding and decodes the bytes back into a string.

Two types make the application/storage distinction explicit:

- **`Encrypted<F>` holds plaintext**, despite its name. It associates a
  value with its field. `expose_secret()` deliberately exposes that value.
- **`Ciphertext<F>` holds the stored encrypted envelope.** It can be
  loaded and passed around before deciding when to decrypt it.

Encryption borrows the source value, so the original plaintext remains available.
Decryption returns a new plaintext-bearing value. Parsing stored bytes checks
their structure; only successful decryption authenticates them.

## A field gives a value its policy

A `UserEmail` **field** says how an email should be handled every time it is
written or read. It is a marker type, separate from the value it stores, so the
same choices are not repeated at each call site. A field declares:

- A **field ID**, the stable identity of the logical field. Every ciphertext and
  blind index is bound to it.
- The **value type**, such as `String`, held by `Encrypted<UserEmail>`.
- A **codec**, such as `Utf8`, to convert between the Rust value and bytes.
- A **padding policy**, which can group different plaintext lengths into the same
  stored size. `Padding::NONE` preserves the encoded length.

The value type is your application's own type: it says how it encodes, never
where it is stored. One `Address` type can back both a `HomeAddress` and a
`BillingAddress` field, each with its own field ID. A value type can name a
default codec by implementing `Plaintext`; `String` and `Vec<u8>` already do.

Field binding ties an email to its field ID. Its ciphertext will not authenticate
under a different field, even if the fields share a root key. Fields that should
read each other's ciphertext declare the same field ID. Binding identifies a
logical field, not a row or tenant: copying ciphertext between rows of the same
field can still succeed.

A field is different from an encryption **suite**. The field describes
application policy; the suite defines the complete cryptographic construction.
CryptBox currently uses suite 1, combining HKDF-SHA-256 key derivation with
XChaCha20-Poly1305 authenticated encryption. The [wire reference](wire-format.md)
defines the exact construction.

## Keys come from the application

A **key provider** supplies key generations. A generation pairs a public ID with
root key material; keeping that pair intact lets a value written today be decrypted
after a restart. The root key itself is never stored in the envelope.

The provider selects a **current generation** for new encryption and resolves
**readable generations** by the exact ID stored in each envelope. Selecting a new
current generation changes future writes; existing ciphertext still needs its
original generation. This is the foundation of key rotation.

Every provider request names the field it serves, so a **router** can assign
fields to different providers, such as a payments key hierarchy for an IBAN and a
general one for an email.

The quickstart passes a local provider explicitly as `&keys`, so no global
installation is needed. For provider and key-context choices, see
[integration design](integration.md#key-providers-and-key-contexts).

## Search uses a separate representation

Encrypting the same email twice produces different ciphertext because encryption
uses a fresh random nonce. Comparing ciphertext therefore cannot answer an
equality query. An optional **blind index** provides a deterministic lookup value
alongside the ciphertext:

```text
                    ┌─ encode → pad if enabled → encrypt → ciphertext
Application value ──┤
                    └─ normalize → derive blind index ───→ lookup value
```

Normalization defines the application's equality rule—for example, lowercasing
text for a case-insensitive lookup. It does not alter the encrypted source value
or depend on its codec or padding. Index derivation uses independently generated
keys and retains a chosen number of digest bits.

A query derives a **probe** for each readable index-key generation. Rows selected
by those probes are **candidates**: each must be authenticated, decrypted, and
compared using the same normalization before acceptance. Truncation allows
different values to share an index, and stored indexes may have been modified.
Blind indexes reveal equality and frequency information; they are not uniqueness
constraints or a guarantee that storage returns every matching row.

## Storage adapters carry the representations

SQLx adapters store ciphertext in `BYTEA` or `BLOB` columns. You can encrypt
explicitly and load `Ciphertext` for later decryption, or use automatic encryption
and decryption at the SQLx boundary. Serde support serializes stored ciphertext
and blind-index bytes; it does not serialize plaintext-bearing `Encrypted` values.

For an indexed value, **`Prepared`** derives ciphertext and indexes from the same
source. Preparation is not persistence: the application writes those
representations atomically and owns transactions and queries. Automatic encryption
of a SQLx column does not maintain its separate index column.

## What to read next

- **Try it:** [encrypt your first field](first-field.md), then
  [store it durably in SQLite](../examples/sqlite/README.md).
- **Apply it:** [integration design and trade-offs](integration.md) explains
  persistent schema, storage boundaries, providers, and search.
- **Assess it:** [security and threat model](security.md) covers protections,
  limitations, and review status.
- **Look something up:** use the [glossary](glossary.md),
  [ownership reference](ownership.md), or [documentation index](README.md#reference).
