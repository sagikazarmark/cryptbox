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

The application keeps working with its own value type. **`Sealed<F>` holds the
stored envelope** of field `F`: `Sealed::seal` produces it, and it can be loaded
and passed around before deciding when to open it.

Sealing borrows the source value, so the original plaintext remains available.
Opening returns a new plaintext value of the field's value type; plaintext hygiene
comes from that type, such as `Secret<String>`. Parsing stored bytes checks their
structure; only successful opening authenticates them.

## A field gives a value its policy

A `UserEmail` **field** says how an email should be handled every time it is
written or read. It is a marker type, separate from the value it stores, so the
same choices are not repeated at each call site. A field declares:

- A **field ID**, the stable identity of the logical field. Every sealed value and
  blind index is bound to it.
- The **value type**, such as `String`, that `Sealed<UserEmail>` opens to.
- A **codec**, such as `Utf8`, to convert between the Rust value and bytes.
- A **padding policy**, which can group different plaintext lengths into the same
  stored size. `Padding::NONE` preserves the encoded length.
- A **binding**: the declared scope each value is bound to, such as a tenant, and
  whether it is also bound to its record. `FieldOnly` binds a value to its field
  ID alone.

The value type is your application's own type: it says how it encodes, never
where it is stored. One `Address` type can back both a `HomeAddress` and a
`BillingAddress` field, each with its own field ID. A value type can name a
default codec by implementing `Plaintext`; `String` and `Vec<u8>` already do.

Every seal and open binds the value at runtime to its field ID, to the values of
the field's binding, and to its record when the field binds one. The binding's
**shape** is persistent schema; its **values**, such as the tenant of the current
request, are passed to each call and must come from an authorized source, never
from the stored row. A sealed email will not authenticate under a different
field, tenant, or record, even if they share a root key. Fields that should read
each other's values declare the same field ID and binding. A `FieldOnly` field
without a record identifies a logical field, not a row or tenant: copying its
values between rows of the same field can still succeed.

A field is different from an encryption **suite**. The field describes
application policy; the suite defines the complete cryptographic construction.
CryptBox currently uses suite 1, combining HKDF-SHA-256 key derivation with
XChaCha20-Poly1305 authenticated encryption. The [wire reference](wire-format.md)
defines the exact construction.

## Keys come from the application

A **keyring** holds key generations. A generation pairs a public ID with
root key material; keeping that pair intact lets a value written today be decrypted
after a restart. The root key itself is never stored in the envelope.

A keyring holds one **current generation** for new encryption and resolves
**readable generations** by the exact ID stored in each envelope. Selecting a new
current generation changes future writes; existing ciphertext still needs its
original generation. This is the foundation of key rotation.

Operations take the keyring to use directly. Choosing which keyring protects a
field, such as a payments key hierarchy for an IBAN and a general one for an
email, is application code: pass the right keyring, or implement a **key source**
that picks one by field or key scope.

The quickstart passes a keyring explicitly as `&keys`, so no global
installation is needed. For keyring and key-context choices, see
[integration design](integration.md#keyrings-and-key-sources).

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

Each blind index is declared over exactly one field. It normalizes the field's
stored value for writes and a lookup input, such as a `str` query, for searches;
both must produce the same bytes for values that should match. Normalizing the
whole value lets an index cover part of it, such as an email domain, or combine
several parts.

A query derives a **probe** for each readable index-key generation. Rows selected
by those probes are **candidates**: each must be authenticated, decrypted, and
compared using the same normalization before acceptance. Truncation allows
different values to share an index, and stored indexes may have been modified.
Blind indexes reveal equality and frequency information; they are not uniqueness
constraints or a guarantee that storage returns every matching row.

## Storage adapters carry the representations

SQLx adapters store sealed values in `BYTEA` or `BLOB` columns. You can seal
explicitly and load `Sealed` for later opening. A `FieldOnly` field without a
record or blind indexes can instead use `Plain<F>`, which seals and opens
automatically at the SQLx boundary; a column decoder sees neither a row nor a
scope, so bound fields are always sealed explicitly. Serde support serializes
sealed values and blind-index bytes; it does not serialize plaintext `Plain`
values.

For an indexed value, **`Prepared`** derives the sealed value and indexes from the
same source. Preparation is not persistence: the application writes those
representations atomically and owns transactions and queries. `Plain<F>` rejects a
field that declares blind indexes, because it would not maintain their columns.

## What to read next

- **Try it:** [encrypt your first field](first-field.md), then
  [store it durably in SQLite](../examples/sqlite/README.md).
- **Apply it:** [integration design and trade-offs](integration.md) explains
  persistent schema, storage boundaries, keys, and search.
- **Assess it:** [security and threat model](security.md) covers protections,
  limitations, and review status.
- **Look something up:** use the [glossary](glossary.md),
  [ownership reference](ownership.md), or [documentation index](README.md#reference).
