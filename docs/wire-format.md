# Wire format

CryptBox stores encrypted values as binary **envelopes**: public metadata followed
by encrypted bytes and an authentication tag. Searchable fields may also have a
separate **blind index**, a deterministic lookup value derived from normalized
plaintext. This document defines both stored representations and the recipes
needed to reproduce them.

| Format | Format version | Suite ID |
| --- | --- | --- |
| [Ciphertext](#envelope) | 2 | [1](#encryption-suite-1) |
| [Blind index](#blind-index-format-1) | 1 | — |

> [!WARNING]
> **These wire formats are experimental.** They may change without backward
> compatibility.
>
> No cryptography review has been conducted yet. A focused review and independently
> generated test vectors are still required.

## Versions and identifiers

The ciphertext envelope carries three identifiers with different jobs:

- **Format version** identifies the envelope structure: how its bytes are parsed.
- **Suite ID** identifies the complete encryption construction: how keys are
  derived, bytes are encrypted, and metadata is authenticated.
- **`KeyId`** identifies the encryption-key generation: which root key the
  provider must supply to decrypt this value. The ID is public; key material is
  never stored in the envelope.

Format version `2` and suite ID `1` are separate identifiers that identify
separate parts of the protocol. Rotating keys
changes the key generation used for new values; it does not change the format
or suite.

Blind indexes have their own format version and `IndexKeyId`. Their format
defines the derivation construction directly, so they have no separate suite ID.

## Encoding and notation

The format layouts and cryptographic recipes below use these conventions:

- UUID identifiers use their 16-byte RFC UUID network-order representation.
- Multibyte integers are unsigned big-endian values.
- Byte literals such as `01`, `80`, and `ff` are hexadecimal.
- `||` concatenates raw bytes.
- `\0` is one NUL byte (`00`).
- Slice endpoints are exclusive.
- Quoted labels are ASCII bytes, without quotes.
- UUID strings and hexadecimal displays represent raw bytes; decode them before
  use rather than hashing their text representation.

## Encryption suite 1

An encryption suite is a complete recipe, rather than just a cipher name.
Agreeing on XChaCha20-Poly1305 alone would not tell another implementation which
key to use or which metadata to authenticate. A suite fixes those choices together
so that a reader can reconstruct exactly the same operation as the writer.

`1` is CryptBox's identifier for the construction defined below. It combines:

- **HKDF-SHA-256** derives a 32-byte operational key from the root key, separating
  its use by format, suite, key generation, and binding. The root key is not used
  directly to encrypt values.
- **XChaCha20-Poly1305** encrypts the plaintext and produces a full 16-byte
  authentication tag. Each encryption uses a fresh 24-byte OS-random nonce, stored
  alongside the ciphertext so decryption can reproduce the operation.
- **Authenticated metadata** ties the encrypted bytes to the exact envelope
  prefix and expected binding. This additional authenticated data (**AAD**) is
  covered by the tag without itself being encrypted.

This is authenticated encryption with associated data (**AEAD**): decryption
returns plaintext only if authentication succeeds. Suite 1 is currently the only
suite CryptBox writes or reads. Suites are built into the library; applications
cannot register their own combinations. An unknown suite ID is rejected before
authentication because the reader has no construction with which to verify it.

### Binding

A binding identifies the expected cryptographic domain of a value. Every value is
bound to a stable `FieldId`, so an email field's ciphertext is not accepted under
a different field, even when both use the same root key. A field-only binding
identifies a logical field, not a particular row or tenant. A
[scoped binding](#scoped-binding) also binds declared scope parts, such as a
tenant, and optionally a record ID. See
[ADR-0005](adr/0005-runtime-binding-is-the-core.md).

A field-only binding is encoded as:

```text
Field(FieldId): 01 || field_id[16]
```

Tag `00` is reserved: earlier releases used it for unbound values, and current
releases neither write nor read it.

The field supplies the expected binding; it is not stored in the envelope.
This makes the application decide where a value belongs, rather than allowing
stored bytes to select their own binding.

#### Scoped binding

A field declares its binding **shape**: a fixed set of parts, each with a part
ID (a UUID), a value kind, and a role, plus whether it binds a record. The shape
is persistent schema. The **values** are supplied at each call. A scoped binding
is encoded as:

```text
Scoped: 02 || field_id[16] || record || count[2] || part*

record = 00                                (no record)
       | kind[1] || len[4] || value[len]   (record present)
part   = part_id[16] || kind[1] || len[4] || value[len]
```

- `count` is the number of parts, as an unsigned 16-bit integer.
- Parts are sorted by part ID in ascending byte order, whatever order the field
  declares them in. Part IDs are unique and never the nil UUID.
- There is at least one part or a record. With neither, the binding is
  field-only and uses tag `01`.
- `len` is an unsigned 32-bit byte count. Every value is length-prefixed, so
  `"ab", "c"` and `"a", "bc"` encode differently.
- A record's kind code is never `00`, so an empty record differs from no record.

Value kinds are fixed and canonical. There is no text kind:

| Kind | Code | Value bytes |
| --- | --- | --- |
| uuid | `01` | 16 raw UUID bytes |
| i64 | `02` | 8 bytes, big-endian two's complement |
| bytes | `03` | raw bytes, as given |

Every part and record value carries its kind code, so the same bytes under
different kinds, such as an `i64` and its 8 big-endian bytes, never collide.
A `keys` part value can't be empty.

#### Shape fingerprint

A scoped envelope's header carries a 64-bit **shape fingerprint**. It covers
the part IDs, kinds, and roles, and the record flag, but no values:

```text
shape label: "cryptbox/binding-shape/v1\0"

fingerprint = SHA-256(shape_label
                      || record_flag[1]
                      || count[2]
                      || (part_id[16] || kind[1] || role[1])*)[0..8]
```

`record_flag` is `01` when the shape binds a record and `00` otherwise. Parts
are sorted by part ID as in the binding, so declaration order does not change
the fingerprint.

| Role | Code | Scopes |
| --- | --- | --- |
| `keys` | `01` | key custody and blind indexes; the unit you shred |
| `index` | `02` | blind indexes only |
| bound only | `03` | the ciphertext only |

Roles are included because a role change alters index derivation and custody,
so it is a migration even though the binding bytes don't change. Field-only
envelopes carry no fingerprint. A record's kind is a runtime value, not part of
the shape: a record of another kind fails authentication rather than reporting
`BindingMismatch`.

#### Reader rules

The fingerprint is diagnostic only. The reader always takes the expected shape
from its own field, never from the envelope:

1. After structural parsing, and before any key lookup or AEAD work, compare the
   envelope's fingerprint with the fingerprint of the reader's shape. A
   field-only reader expects none. Any difference, including a fingerprint
   where none is expected or the reverse, reports `BindingMismatch`.
2. Otherwise, decrypt with the binding built from the reader's shape and the
   caller's values. Different part or record values under a matching shape fail
   authentication.

The fingerprint is part of the authenticated prefix. Changing it to match
another shape that has the same binding bytes, such as a role change, still
fails authentication.

Codec identity and version are also absent: the application schema must supply
them to interpret the plaintext after authentication. Whether the payload is
padded is recorded in the envelope flags; padding parameters are not.

### Envelope

Ciphertext format 2 starts with a 23-byte header containing the magic bytes,
format version, suite ID, flags, and `KeyId`. The suite determines the remaining
layout. For suite 1, the nonce extends that header to a 47-byte prefix:

```text
offset  size  field
0       4     43 42 58 00 ("CBX" + NUL)
4       1     format version = 02
5       1     suite ID = 01
6       1     flags
7       16    KeyId
23      24    XChaCha20 nonce
47      N     ciphertext
47+N    16    Poly1305 tag
```

A [scoped binding](#scoped-binding) extends the header to 31 bytes with its
[shape fingerprint](#shape-fingerprint). For suite 1 the prefix is then 55
bytes:

```text
offset  size  field
0       23    header, as above, with flag bit 02 set
23      8     shape fingerprint
31      24    XChaCha20 nonce
55      N     ciphertext
55+N    16    Poly1305 tag
```

Flag bit `01` records that the AEAD plaintext is [padded](#plaintext-padding).
Flag bit `02` records a scoped binding, so the shape fingerprint follows the
`KeyId`. A field-only envelope leaves it clear and is byte-identical to earlier
format 2 envelopes. The format version stays `2`: readers that predate bit `02`
reject it as reserved, so they never misparse a scoped header. All other bits
are reserved and must be zero; readers reject an envelope with a reserved bit
set before authentication. The flags are part of the authenticated prefix, so
changing them fails authentication or, for bit `02`, reports `BindingMismatch`
under the [reader rules](#reader-rules).

There is no embedded payload-length field: the enclosing storage or transport
must supply the envelope boundary. Within that boundary, the last 16 bytes are
the tag and the bytes between the prefix and tag are the encrypted payload.
The prefix is readable without a key, but remains untrusted until authentication.

The minimum envelope is 63 bytes (71 when scoped) and represents empty AEAD
plaintext. For an
unpadded value, ciphertext leaks encoded plaintext length exactly plus this
fixed overhead. A padded value reveals its padded bucket length instead.
See [size semantics and enforcement](#size-semantics-and-enforcement) for exact
encoded, padded, and stored lengths and the suite's functional limit.

### Key derivation and authenticated data

Fixed labels keep cryptographic operations for different purposes distinct,
even when other inputs overlap. These labels are protocol bytes, not descriptive
names that an implementation can change. Each includes its terminating NUL byte:

```text
HKDF salt:      "cryptbox/hkdf-sha256/v1\0"
key info label: "cryptbox/encryption-key/v1\0"
AAD label:      "cryptbox/envelope-aad/v1\0"
```

```text
key_info = key_info_label
        || format_version
        || suite_id
        || key_id
        || binding

aad = aad_label || prefix || binding
```

`prefix` is the whole suite prefix, including the shape fingerprint when
present: `envelope[0..47]`, or `envelope[0..55]` when scoped.

### Encryption recipe

Inputs are an independent 32-byte encryption root, its immutable 16-byte
`KeyId`, the expected field binding, and AEAD plaintext bytes (encoded and
optionally padded as below), and whether it is padded. Use the encoding
conventions and binding bytes above, with `format_version = 02` and
`suite_id = 01`. Rust type names and database names are not inputs.

1. Construct `key_info` in the order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, root_key)` (32-byte PRK), then
   `operational_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   Use the fixed HKDF salt above, not the nonce.
2. Generate a fresh 24-byte nonce from the operating-system random source for
   each encryption, failing if randomness is unavailable. The fixed nonces in
   the vectors are test inputs only, not a supported application nonce policy.
3. Construct the 47-byte prefix from magic, version, suite, flags, `KeyId`, and
   nonce using the offset table. Set flag bit `01` exactly when the AEAD
   plaintext is padded. For a scoped binding, set flag bit `02` and insert the
   shape fingerprint before the nonce, giving a 55-byte prefix. Form
   `aad = aad_label || prefix || binding`.
4. Seal the complete AEAD plaintext with XChaCha20-Poly1305 using the 32-byte
   operational key, nonce, and AAD. Append the ciphertext (same length as AEAD
   plaintext) and the full 16-byte tag to the prefix. No text encoding, tag
   truncation, or additional delimiters are applied.

For decryption, structurally validate the envelope, check its shape fingerprint
under the [reader rules](#reader-rules), resolve only its exact `KeyId`,
reconstruct the key and AAD with the **expected** binding, and verify
the tag before returning any plaintext. Only after authentication is padding
removed, when the authenticated flag is set, and the value decoded; the reader's
current padding policy never decides whether to remove padding. Wrong binding
values or changes to supported metadata, flags, nonce, ciphertext, or tag fail
authentication. Malformed/unsupported envelopes, a different binding shape, and
unknown keys can fail before authentication. Successful decryption does not
establish freshness or row identity.

### Plaintext padding

Encryption preserves payload length, so padding lets a field hide the exact
encoded length by expanding it to a block boundary or fixed target. Suite 1 does
not require padding; it can encrypt any byte length within its size limit.

Padded values use ISO/IEC 7816-4 padding before the encoded plaintext is passed
to the encryption suite. Padding appends one `80` byte followed by as many `00`
bytes as needed to reach the selected block or fixed length. Removal scans
backward over zero bytes, requires the `80` marker, and strips it. It does not
depend on the block size or fixed length that produced the padding.

For encoded length `E`, `Padding::NONE` passes through `E` bytes;
`Padding::block(N)` (`N >= 2`) produces `N * ceil((E + 1) / N)` bytes; and
`Padding::length(N)` (`N >= 1`) produces exactly `N` bytes, rejecting `E >= N`
because the marker must fit. An aligned block input receives a whole extra
block, and even an empty padded input contains a marker.

The writer sets the padded flag exactly when it applies padding, and a reader
removes padding exactly when the authenticated flag is set. The reader's current
padding policy is not consulted, so padded bytes are never returned with their
marker, and an unpadded value ending in `80` or `80 00` never loses those bytes.
A field's padding policy therefore describes only how new values are written: it
can be enabled, disabled, or resized without making stored values unreadable.
Re-encryption rewrites the payload and flag with the field's current policy.
The byte-level `encrypt` function takes the policy to apply; `decrypt` removes
recorded padding.

The block size or fixed length is not recorded. Changing only those parameters
is not visible in the envelope, so re-encryption applies them only to values it
rewrites for another reason.

### Size semantics and enforcement

All lengths are byte counts, not character counts or Rust memory sizes:

| Quantity | Definition |
| --- | --- |
| `E`: encoded bytes | Codec output before padding. `Utf8` counts UTF-8 bytes: `"é"` has `E = 2`. |
| `P`: AEAD plaintext | Encoded bytes after padding, including the marker and zero fill when enabled. `Padding::NONE` gives `P = E`. |
| `W`: envelope bytes | Complete binary ciphertext: 47-byte prefix, `P` ciphertext bytes, 16-byte tag. `W = P + 63`, or `P + 71` with a scoped binding's 55-byte prefix; excludes text encoding, database framing, and separate indexes. |

Padding boundary examples (ASCII input, one encoded byte per character):

| Padding policy | `E` | Padding bytes | `P` | `W` | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `Padding::NONE` | 0 | 0 | 0 | 63 | Accepted |
| `Padding::NONE` | 16 | 0 | 16 | 79 | Exact length preserved |
| `Padding::block(16)` | 0 | 16 | 16 | 79 | Empty input still padded |
| `Padding::block(16)` | 15 | 1 | 16 | 79 | Marker fills block |
| `Padding::block(16)` | 16 | 16 | 32 | 95 | Marker starts next block |
| `Padding::length(16)` | 0 | 16 | 16 | 79 | Empty input uses entire target |
| `Padding::length(16)` | 15 | 1 | 16 | 79 | Largest fitting input |
| `Padding::length(16)` | 16 | — | — | — | `PaddingOverflow`: marker cannot fit |

Suite 1 enforces RFC 8439's functional maximum `P <= 274,877,906,880`
(`(2^32 - 1) * 64`) on encryption and rejects parsed/decrypted payloads implying
a larger `P`, with `MessageTooLong`. Padding/envelope size arithmetic is checked;
fixed padding rejects `E >= N` with `PaddingOverflow`. This is an algorithmic
ceiling, not a recommended field size. Applications must choose smaller limits
appropriate to their workloads; see
[application responsibilities](security.md#application-responsibilities).

For an application-selected padded cap `L`, `Padding::NONE` permits `E <= L`;
`Padding::block(N)` permits `E <= N * floor(L / N) - 1` if at least one block fits;
`Padding::length(N)` requires `N <= L` and `E <= N - 1`. Bound encoding and compute
padded size with checked arithmetic before allocating/encrypting. Bound incoming
binary envelopes to `W <= L + 63` (`L + 71` for a scoped field) before
copying/decrypting, and bound decoding
expansion separately; a [format 1](#format-1) envelope is one byte shorter, so
the same bound admits it. Current padding parameters do not cap historical reads:
unpadding accepts a valid marker independently of the original block/target size.
A size check is not authentication.

### Key and buffer lifetime

See [plaintext and key ownership](ownership.md) for buffer lifetimes and erasure
obligations.

### Provisional envelope vectors

These fixed inputs and expected outputs help check byte-for-byte compatibility.
The first vector encrypts unpadded plaintext (flags `00`) bound to
`FieldId 12345678-1234-4234-8234-1234567890ab`:

```text
root key:   1111111111111111111111111111111111111111111111111111111111111111
KeyId:      11111111-2222-4333-8444-555555555555
binding:    01123456781234423482341234567890ab
plaintext:  6372797074626f7820766563746f72 ("cryptbox vector")
nonce:      000102030405060708090a0b0c0d0e0f1011121314151617
envelope:   4342580002010011111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd4f8e9c4e8454cd34732e7966a50994cd
```

The padded vector uses the same root key, `KeyId`, binding, and nonce as the
first vector, with `"cryptbox vector"` padded under `Padding::block(16)` and
flags `01`:

```text
padded plaintext: 6372797074626f7820766563746f7280
envelope:         4342580002010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f10111213141516173f7195595232290da92d72b42bb6fd489a56ec6e125f07deaa76f7502ad2613f
```

Both decrypt to `"cryptbox vector"` whatever the reader's padding policy. The
vectors are generated and consumed in separate tests, but they have not yet been
cross-checked against an independent implementation.

### Provisional scoped vectors

These vectors use the root key, `KeyId`, `FieldId`, plaintext, and nonce above,
unpadded, with a [scoped binding](#scoped-binding) of two parts:

```text
part 11111111-1111-1111-1111-111111111111  uuid   keys        33333333-3333-3333-3333-333333333333
part 22222222-2222-2222-2222-222222222222  bytes  bound only  77732d31 ("ws-1")
```

Without a record, the shape fingerprint is `cda083fe6eae1bf1`:

```text
binding:  02123456781234423482341234567890ab0000021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31
envelope: 4342580002010211111111222243338444555555555555cda083fe6eae1bf1000102030405060708090a0b0c0d0e0f1011121314151617b51d411fdf173c5725d9000dae571d2bc413649bd09198dd576ab7879aeb42
```

With the `i64` record `7`, the shape fingerprint is `505a9cd2bc286636`:

```text
binding:  02123456781234423482341234567890ab0200000008000000000000000700021111111111111111111111111111111101000000103333333333333333333333333333333322222222222222222222222222222222030000000477732d31
envelope: 4342580002010211111111222243338444555555555555505a9cd2bc286636000102030405060708090a0b0c0d0e0f10111213141516172619b76ce657aac8910c65d99b49a02880a201078edb80702123597f908f71
```

Both fingerprints and bindings were computed independently of the
implementation from the recipes above. The envelopes have not yet been
cross-checked against an independent implementation.

### Format 1

Ciphertext format 1 is the previous envelope. It is still read, but no longer
written. It has no flags byte: a 22-byte header (magic, `01`, suite ID, `KeyId`)
and, for suite 1, a 46-byte prefix, so `W = P + 62`. Key derivation uses
`format_version = 01`, and the AAD covers `envelope[0..46]`; otherwise the
recipe is unchanged.

Format 1 does not record whether its payload is padded. A reader removes padding
exactly when the field's **current** padding policy pads, which is how format 1
was written. This is correct only while the policy is unchanged: a padded value
read without padding keeps its `80 00…` bytes, and an unpadded value read with
padding fails with `InvalidPadding` or loses trailing `80`/`80 00` bytes. The
byte-level `decrypt` function has no policy and returns a format 1 payload as
stored.

A format 1 envelope always needs re-encryption, which rewrites it as format 2
using the current policy. Sweep stored format 1 values before changing a field's
padding policy. These format 1 vectors use the inputs above:

```text
unpadded envelope: 43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfceb1074e9691ed9f65c6b1ee8ddf1219d
padded envelope:   43425800010111111111222243338444555555555555000102030405060708090a0b0c0d0e0f101112131415161790fc94db1267819912c4b5abc48bfce28615aa60f3cc8e8475dbf73c2d43d9f6
```

## Blind-index format 1

A blind index supports equality-style lookup without decrypting every stored
value. Normalization gives values the application considers equivalent the same
bytes—for example, by lowercasing text for a case-insensitive index. For a given
index policy and key generation, the same normalized bytes produce the same
index bytes. Unlike randomized ciphertext, this deliberately reveals equality
and frequency information.

Format `1` defines both the stored layout and the derivation recipe:
HKDF-SHA-256 derives an index-specific key, HMAC-SHA-256 computes a keyed digest
of the normalized value and its context, and truncation retains only the selected
number of most-significant bits. Fewer retained bits mean more false candidates.
Root blind-index keys must be independent from encryption keys.

### Stored layout

```text
offset  size          field
0       1             format version = 01
1       16            IndexKeyId
17      2             retained bit count
19      ceil(bits/8)  truncated HMAC
```

`IndexKeyId` identifies the root-key generation, while the retained bit count
records the index precision. Valid precision is 1 through 256 bits, giving a total
stored length of 20 through 51 bytes. For non-byte-aligned precision, unused low
bits in the final byte are zero and noncanonical stored values are rejected.

### Key derivation and index input

The logical `IndexId` distinguishes indexes, such as two differently normalized
projections of the same field. It is separate from `IndexKeyId`: one identifies
the index's meaning, the other its key generation. `IndexId`, binding, and
normalization come from the application schema and are not stored in the index.

Exact domain labels include the terminating NUL byte:

```text
key info label: "cryptbox/blind-index-key/v1\0"
MAC label:      "cryptbox/blind-index-value/v1\0"
HKDF salt:      "cryptbox/hkdf-sha256/v1\0"
```

```text
header = format_version || index_key_id || bits_be
context = header || binding || index_id
key_info = key_info_label || context
mac_input = MAC_label || context || normalized_length_be_u64 || normalized_bytes
```

### Blind-index recipe

Inputs are an independent 32-byte blind-index root (never an encryption root),
its immutable `IndexKeyId`, the expected binding, logical `IndexId`, retained
bit count, and normalized bytes. `IndexKeyId`, `IndexId`, and any `FieldId` are
encoded using the UUID convention above, and binding uses the same encoding as
encryption. The version is one byte `01`; `bits_be` is a two-byte unsigned
big-endian count in `1..=256`.

1. Run the application's deterministic normalizer for this logical index.
   There is no built-in case folding, Unicode normalization, or text encoding
   at this layer. Use identical normalization for writes, probes, and candidate
   comparisons. Normalized bytes are independent of the encryption codec and
   padding. Their length is a **byte count**, encoded as unsigned big-endian
   `u64` (eight bytes); a length that cannot fit is invalid.
2. Construct the 19-byte `header`, then `context`, then `key_info` in the exact
   order above. Perform **both** RFC 5869 stages:
   `PRK = HKDF-Extract-SHA256(salt, blind_index_root)` (32-byte PRK), then
   `index_key = HKDF-Expand-SHA256(PRK, key_info, L=32)`.
   Use the fixed HKDF salt above. No nonce is used, so derivation is deterministic.
3. Compute the full 32-byte `HMAC-SHA256(index_key, mac_input)`. Concatenation adds
   no separators or terminators beyond those explicitly shown; in particular,
   normalized bytes have no implicit NUL terminator.
4. Retain the first `ceil(bits / 8)` digest bytes, keeping the most-significant
   `bits` bits. If `r = bits mod 8` is nonzero, AND the final byte with
   `(ff << (8 - r)) & ff`. Append this canonical truncated digest to `header`.
   The stored representation is exactly `19 + ceil(bits / 8)` bytes, with no
   encryption envelope, nonce, or additional tag.

Structural parsing rejects unsupported versions, precision outside `1..=256`,
incorrect total length (including trailing bytes), or nonzero unused low bits.
A typed `BlindIndex<Spec>` additionally requires the stored precision to equal
`Spec::BITS`. Parsing checks structure only; it does not authenticate the stored
metadata or prove consistency with ciphertext. Because truncation allows different
values to share an index, index hits remain candidates requiring authenticated
decryption and normalized plaintext comparison. See the
[verified search example](../examples/searchable/README.md) for using these bytes in a query.

### Provisional blind-index vector

```text
root key:     2222222222222222222222222222222222222222222222222222222222222222
IndexKeyId:   aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
IndexId:      abcdefab-cdef-4def-8def-abcdefabcdef
FieldId:      12345678-1234-4234-8234-1234567890ab
binding:      01123456781234423482341234567890ab
bits:         13
normalized:   6e6f726d616c697a6564406578616d706c652e636f6d ("normalized@example.com")
stored value: 01aaaaaaaabbbb4ccc8dddeeeeeeeeeeee000d71e0
```

The final byte `e0` has its three unused low bits cleared. This vector has not
yet been cross-checked against an independent implementation.
